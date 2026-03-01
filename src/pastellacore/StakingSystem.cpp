// Copyright (c) 2026, The Pastella Team
//
// Simple Reward Staking System Implementation
// Please see the included LICENSE file for more information.

#include "StakingSystem.h"
#include <config/PastellaConfig.h>
#include <common/StringTools.h>
#include <common/Base58.h>
#include <utilities/Addresses.h>
#include <crypto/crypto.h>
#include <serialization/SerializationOverloads.h>
#include <stdexcept>
#include <iostream>
#include <algorithm>

using namespace Crypto;

namespace Pastella
{
    /* StakingPool Implementation */
    StakingPool::StakingPool() :
        totalPoolBalance(0), totalStakedAmount(0), currentBlockHeight(0), isHistoricalRewardsInitialized(false)
    {
    }

    bool StakingPool::initialize()
    {
        totalPoolBalance = 0;
        totalStakedAmount = 0;
        currentBlockHeight = 0;
        activeStakes.clear();
        blockRewardContributions.clear();
        return true;
    }

    uint64_t StakingPool::calculateBlockReward(uint64_t height, uint64_t alreadyGeneratedCoins) const
    {
        // Calculate current halving level using the same logic as Currency class
        uint32_t halvingLevel = 0;
        for (uint32_t i = 0; i < Pastella::parameters::HALVING_HEIGHTS_COUNT; i++) {
            if (height > Pastella::parameters::HALVING_HEIGHTS[i]) {
                halvingLevel++;
            } else {
                break;
            }
        }

        // Calculate reward with halving applied
        uint64_t baseReward = Pastella::parameters::BLOCK_REWARD;
        for (uint32_t i = 0; i < halvingLevel; i++) {
            baseReward /= 2;
        }

        // Minimum reward threshold (stop mining when reward is too small)
        const uint64_t MIN_REWARD_THRESHOLD = 1;  // 0.00000001 PAS (1 atomic unit)
        if (baseReward < MIN_REWARD_THRESHOLD) {
            return 0;
        }

        return baseReward;
    }

    bool StakingPool::restoreStakingTransaction(const std::string &txHash,
                                            uint64_t amount, uint64_t unlockTime, uint32_t lockDurationDays,
                                            uint64_t creationHeight, uint64_t currentBlockchainHeight)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Check if this stake already exists
        if (activeStakes.find(txHash) != activeStakes.end())
        {
            return true;
        }

        // Create restored stake entry
        // TRANSPARENT SYSTEM: stakerAddress will be set by updateStakeStakerAddress
        StakingEntry entry;
        entry.stakingTxHash = txHash;
        entry.amount = amount;
        entry.lockDurationDays = lockDurationDays;
        entry.unlockTime = unlockTime;
        entry.accumulatedReward = 0; // Will be calculated below if completed
        entry.lastCalculatedBlock = creationHeight;
        entry.creationHeight = creationHeight;
        entry.stakerAddress = ""; // Will be set from transaction inputs during restoration

        // Check if stake has completed based on current blockchain height
        if (currentBlockchainHeight >= unlockTime) {
            // Stake has completed - mark as inactive and calculate accumulated reward
            entry.isActive = false;

            // Calculate blocks staked
            if (entry.creationHeight == 0 || currentBlockchainHeight <= entry.creationHeight) {
                entry.blocksStaked = 0;
            } else {
                /* Calculate blocks until staking period ends (unlockTime) */
                uint64_t stakingEndHeight = unlockTime;

                /* If staking period has ended, cap blocks at unlockTime */
                if (currentBlockchainHeight >= stakingEndHeight) {
                    entry.blocksStaked = stakingEndHeight - entry.creationHeight;
                } else {
                    entry.blocksStaked = currentBlockchainHeight - entry.creationHeight;
                }

                /* Cap at reasonable maximum (2 years worth of blocks) */
                const uint64_t MAX_BLOCKS = 2 * 365 * 2880; /* 2 years, 2880 blocks/day */
                if (entry.blocksStaked > MAX_BLOCKS) {
                    entry.blocksStaked = MAX_BLOCKS;
                }
            }

            /* Get daily reward rate */
            uint32_t dailyRewardRate = getRewardRateForLockPeriod(entry.lockDurationDays);
            if (dailyRewardRate == 0) {
                entry.accumulatedReward = 0;
            } else {
                /* Calculate yearly reward directly for maximum precision */
                entry.estYearlyReward = (entry.amount * dailyRewardRate) / 100;

                /* Calculate daily reward from yearly for perfect consistency */
                entry.estDailyReward = entry.estYearlyReward / 365;

                /* Calculate accumulated rewards based on blocks staked */
                /* Blocks per day = 86400 seconds / 30 seconds per block = 2880 blocks/day */
                const uint64_t BLOCKS_PER_DAY = 2880;
                if (entry.blocksStaked > 0) {
                    /* Calculate days staked from blocks */
                    double daysStaked = static_cast<double>(entry.blocksStaked) / BLOCKS_PER_DAY;
                    /* Calculate accumulated rewards using daily reward */
                    entry.accumulatedReward = static_cast<uint64_t>(static_cast<double>(entry.estDailyReward) * daysStaked + 0.5);
                    /* Also keep accumulatedEarnings for backward compatibility */
                    entry.accumulatedEarnings = entry.accumulatedReward;
                } else {
                    entry.accumulatedReward = 0;
                    entry.accumulatedEarnings = 0;
                }
            }
        } else {
            // Stake is still active
            entry.isActive = true;
        }

        // Add to active stakes
        activeStakes[txHash] = entry;

        // Only add to totalStakedAmount if the stake is still active
        if (entry.isActive) {
            totalStakedAmount += amount;
        }

        return true;
    }

    bool StakingPool::addTransactionFee(uint64_t fee)
    {
        // Transaction fees should NOT go to staking pool
        // They go to miners. This function is kept for compatibility but does nothing.
        return true;
    }

    uint64_t StakingPool::getAvailableBalance() const
    {
        return totalPoolBalance;
    }

    uint64_t StakingPool::getTotalStakedAmount() const
    {
        return totalStakedAmount;
    }

    uint64_t StakingPool::getTotalPoolBalance() const
    {
        return totalPoolBalance;
    }

    uint64_t StakingPool::getTotalPaidStakingRewards() const
    {
        uint64_t totalPaidRewards = 0;

        // Sum accumulated rewards only from INACTIVE stakes (those that have been paid out)
        for (const auto &pair : activeStakes) {
            const StakingEntry &entry = pair.second;

            if (!entry.isActive) {
                // Only count rewards from stakes that are no longer active (completed/paid out)
                totalPaidRewards += entry.accumulatedReward;
            }
        }

        return totalPaidRewards;
    }

    bool StakingPool::addStake(const std::string &txHash,
                              const std::string &stakerAddress, uint64_t amount, uint32_t lockDurationDays, uint64_t creationHeight)
    {
        if (!validateMinimumAmount(amount))
        {
            return false;
        }

        if (!validateLockDuration(lockDurationDays))
        {
            return false;
        }

        // TRANSPARENT SYSTEM: Store staker's address (where rewards will be sent)
        StakingEntry entry;
        entry.stakingTxHash = txHash;
        entry.stakerAddress = stakerAddress;
        entry.amount = amount;
        entry.lockDurationDays = lockDurationDays;
        entry.unlockTime = calculateUnlockTime(lockDurationDays, creationHeight);
        entry.accumulatedReward = 0;
        entry.lastCalculatedBlock = creationHeight;
        entry.isActive = true;
        entry.creationHeight = creationHeight;

        activeStakes[txHash] = entry;
        totalStakedAmount += amount;

        return true;
    }

    uint64_t StakingPool::calculateReward(uint64_t amount, uint32_t lockDurationDays,
                                         uint64_t blocksStaked) const
    {
        uint32_t dailyRate = getRewardRateForLockPeriod(lockDurationDays);
        if (dailyRate == 0)
        {
            return 0;
        }

        // Calculate daily reward in atomic units (avoid overflow)
        uint64_t dailyReward = (amount / 10000000000ULL) * dailyRate +
                              ((amount % 10000000000ULL) * dailyRate) / 10000000000ULL;

        // Total reward = daily reward * number of days
        uint64_t daysStaked = blocksStaked * 30 / 86400; // Approximate days (30s block time)
        uint64_t totalReward = dailyReward * daysStaked;

        return totalReward;
    }

    uint64_t StakingPool::getPendingRewards(const std::string &address) const
    {
        // Since we no longer track rewards by address, return 0
        // This method should be updated to use transaction hash-based lookups instead
        return 0;
    }

    bool StakingPool::calculateDetailedRewards(Pastella::StakingEntry &entry, uint64_t currentHeight) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        /* Calculate blocks staked - use reasonable defaults if data is missing */
        if (entry.creationHeight == 0 || currentHeight <= entry.creationHeight)
        {
            entry.blocksStaked = 0;
        }
        else
        {
            /* Calculate blocks until staking period ends (unlockTime) */
            uint64_t stakingEndHeight = entry.unlockTime;

            /* If staking period has ended, cap blocks at unlockTime */
            if (currentHeight >= stakingEndHeight)
            {
                entry.blocksStaked = stakingEndHeight - entry.creationHeight;
            }
            else
            {
                entry.blocksStaked = currentHeight - entry.creationHeight;
            }

            /* Cap at reasonable maximum (2 years worth of blocks) */
            const uint64_t MAX_BLOCKS = 2 * 365 * 2880; /* 2 years, 2880 blocks/day */
            if (entry.blocksStaked > MAX_BLOCKS)
            {
                entry.blocksStaked = MAX_BLOCKS;
            }
        }

        /* Get daily reward rate */
        entry.dailyRewardRate = getRewardRateForLockPeriod(entry.lockDurationDays);
        if (entry.dailyRewardRate == 0)
        {
            return false;
        }

        /* Calculate daily and yearly rewards more carefully to prevent overflow */
        /* Formula: Amount × Rate / 100 (since rates are percentages, not per-thousand) */
        /* Daily: Amount × Rate / 100 / 365 */
        /* Yearly: Amount × Rate / 100 */

        /* Calculate yearly reward directly for maximum precision */
        entry.estYearlyReward = (entry.amount * entry.dailyRewardRate) / 100;

        /* Calculate daily reward from yearly for perfect consistency */
        entry.estDailyReward = entry.estYearlyReward / 365;

        /* Calculate projections */
        entry.estWeeklyReward = (entry.estYearlyReward * 7) / 365;
        entry.estMonthlyReward = (entry.estYearlyReward * 30) / 365;

        /* Calculate accumulated rewards based on blocks staked */
        /* Blocks per day = 86400 seconds / 30 seconds per block = 2880 blocks/day */
        const uint64_t BLOCKS_PER_DAY = 2880;
        if (entry.blocksStaked > 0) {
            /* Calculate days staked from blocks */
            double daysStaked = static_cast<double>(entry.blocksStaked) / BLOCKS_PER_DAY;
            /* Calculate accumulated rewards using daily reward and store in accumulatedReward field */
            entry.accumulatedReward = static_cast<uint64_t>(static_cast<double>(entry.estDailyReward) * daysStaked + 0.5);
            /* Also keep accumulatedEarnings for backward compatibility */
            entry.accumulatedEarnings = entry.accumulatedReward;
        } else {
            entry.accumulatedReward = 0;
            entry.accumulatedEarnings = 0;
        }

        /* Calculate total reward at maturity (for the full lock duration) */
        entry.totalRewardAtMaturity = (entry.estDailyReward * entry.lockDurationDays);

        return true;
    }

    std::vector<StakingEntry> StakingPool::getActiveStakes() const
    {
        std::vector<StakingEntry> result;
        for (const auto &pair : activeStakes)
        {
            if (pair.second.isActive)
            {
                result.push_back(pair.second);
            }
        }

        return result;
    }

    std::vector<StakingEntry> StakingPool::getInactiveStakes() const
    {
        std::vector<StakingEntry> result;
        for (const auto &pair : activeStakes)
        {
            if (!pair.second.isActive)
            {
                result.push_back(pair.second);
            }
        }

        return result;
    }


    std::vector<StakingEntry> StakingPool::getStakesByHashes(const std::vector<std::string> &stakingTxHashes) const
    {
        std::vector<StakingEntry> result;
        for (const auto &pair : activeStakes)
        {
            // Check if this stake's hash is in the requested hash list
            const auto &hash = pair.second.stakingTxHash;
            if (std::find(stakingTxHashes.begin(), stakingTxHashes.end(), hash) != stakingTxHashes.end())
            {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    std::vector<StakingEntry> StakingPool::getStakesByAddress(const std::string &stakerAddress) const
    {
        std::vector<StakingEntry> result;
        for (const auto &pair : activeStakes)
        {
            // Check if this stake belongs to the requested address
            if (pair.second.stakerAddress == stakerAddress)
            {
                result.push_back(pair.second);
            }
        }
        return result;
    }


    bool StakingPool::validateLockDuration(uint32_t lockDurationDays) const
    {
        return isValidLockPeriod(lockDurationDays);
    }

    bool StakingPool::validateMinimumAmount(uint64_t amount) const
    {
        return amount >= Pastella::parameters::staking::MIN_STAKING_AMOUNT;
    }


    /* StakingValidator Implementation */
    bool StakingValidator::validateStakingTransaction(const TransactionExtraStaking &stakingData,
                                                     const TransactionPrefix &tx,
                                                     const Pastella::IBlockchainCache *blockchainCache,
                                                     uint64_t currentHeight)
    {
        if (!isValidStakingType(stakingData.stakingType))
        {
            return false;
        }

        if (stakingData.stakingType != Pastella::parameters::staking::STAKING_TX_TYPE)
        {
            return false;
        }

        // Validate minimum amount
        if (stakingData.amount < Pastella::parameters::staking::MIN_STAKING_AMOUNT)
        {
            return false;
        }

        // CRITICAL: Verify signature proves ownership of staked funds
        // The signature must prove the staker owns the UTXOs being staked
        if (!verifyStakingSignatureForTransaction(stakingData, tx, blockchainCache))
        {
            return false;
        }

        // Validate lock duration
        if (!isValidLockPeriod(stakingData.lockDurationDays))
        {
            return false;
        }

        // Validate unlock time corresponds to the lock duration
        // Calculate what the unlock time should be for the given lock period
        uint64_t expectedUnlockTimeForDuration = calculateUnlockTime(stakingData.lockDurationDays, 0); // Height 0 to get pure duration
        uint64_t actualDuration = stakingData.unlockTime - currentHeight; // How many blocks from current height

        // Allow some tolerance (±15 blocks) for timing differences
        uint64_t tolerance = 15;
        if (actualDuration < (expectedUnlockTimeForDuration - tolerance) ||
            actualDuration > (expectedUnlockTimeForDuration + tolerance))
        {
            return false;
        }

              // stakingTxHash field removed from transaction extra data - transaction hash is inherent

        // TRANSPARENT SYSTEM: rewardAddress validation removed - rewards go to wallet's main address

        // Validate signature is present and not empty (check if all bytes are zero)
        bool signatureEmpty = true;
        for (size_t i = 0; i < sizeof(stakingData.signature.data); ++i)
        {
            if (stakingData.signature.data[i] != 0)
            {
                signatureEmpty = false;
                break;
            }
        }

        if (signatureEmpty)
        {
            return false;
        }

        // Basic signature format check (Crypto::Signature has 64 bytes)
        return true;
    }

    bool StakingValidator::verifyStakingSignatureForTransaction(const TransactionExtraStaking &stakingData,
                                                                const TransactionPrefix &tx,
                                                                const Pastella::IBlockchainCache *blockchainCache)
    {
        /* CRITICAL SECURITY: Verify the signature proves ownership of the staked funds
         *
         * In a transparent system, each input references a specific UTXO with a public key
         * The signature must prove that the staker owns the private key corresponding to
         * the public key of at least one input being spent.
         *
         * Message to sign = hash(amount + lockDurationDays + unlockTime)
         * Signature must be verifiable with the public key from one of the transaction inputs */

        // Check if signature is present and not all zeros
        bool signatureEmpty = true;
        for (size_t i = 0; i < sizeof(stakingData.signature.data); ++i)
        {
            if (stakingData.signature.data[i] != 0)
            {
                signatureEmpty = false;
                break;
            }
        }

        if (signatureEmpty)
        {
            // Signature is all zeros - invalid
            return false;
        }

        // Check signature has entropy (not all same bytes)
        bool allSame = true;
        uint8_t firstByte = stakingData.signature.data[0];
        for (size_t i = 1; i < sizeof(stakingData.signature.data); ++i)
        {
            if (stakingData.signature.data[i] != firstByte)
            {
                allSame = false;
                break;
            }
        }

        if (allSame)
        {
            // Signature lacks entropy - likely invalid
            return false;
        }

        // Construct the message that should have been signed
        // Message = hash(amount + lockDurationDays + unlockTime)
        std::vector<uint8_t> message;
        message.reserve(sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint64_t));

        // Add amount
        const uint8_t* amountBytes = reinterpret_cast<const uint8_t*>(&stakingData.amount);
        message.insert(message.end(), amountBytes, amountBytes + sizeof(uint64_t));

        // Add lockDurationDays
        const uint8_t* lockBytes = reinterpret_cast<const uint8_t*>(&stakingData.lockDurationDays);
        message.insert(message.end(), lockBytes, lockBytes + sizeof(uint32_t));

        // Add unlockTime
        const uint8_t* unlockBytes = reinterpret_cast<const uint8_t*>(&stakingData.unlockTime);
        message.insert(message.end(), unlockBytes, unlockBytes + sizeof(uint64_t));

        // Hash the message
        Crypto::Hash messageHash;
        Crypto::cn_fast_hash(message.data(), message.size(), messageHash);

        // IMPORTANT: During mempool validation, blockchainCache may be NULL
        // In this case, we SKIP signature verification and allow the transaction
        // The transaction will be properly validated when included in a block
        if (blockchainCache == nullptr)
        {
            return true; // Accept transaction - will be verified when mined
        }

        // Try to verify signature against each input's public key
        // In transparent system, each KeyInput references a transactionHash and outputIndex
        // We need to get the public key from at least one input and verify the signature
        bool signatureVerified = false;

        for (const auto& input : tx.inputs)
        {
            if (input.type() == typeid(Pastella::KeyInput))
            {
                const Pastella::KeyInput& keyInput = boost::get<Pastella::KeyInput>(input);

                /* Get the transaction that contains the UTXO being spent */
                try
                {
                    std::vector<Crypto::Hash> txHashes = {keyInput.transactionHash};
                    std::vector<Pastella::BinaryArray> txBinaries = blockchainCache->getRawTransactions(txHashes);

                    if (!txBinaries.empty() && !txBinaries[0].empty())
                    {
                        /* Use CachedTransaction to parse and access the transaction */
                        Pastella::CachedTransaction cachedTx(txBinaries[0]);
                        const Pastella::Transaction& referencedTx = cachedTx.getTransaction();

                        /* Get the output being spent */
                        if (keyInput.outputIndex < referencedTx.outputs.size())
                        {
                            const auto& output = referencedTx.outputs[keyInput.outputIndex];

                            /* Extract public key from output (KeyOutput type) */
                            if (output.target.type() == typeid(Pastella::KeyOutput))
                            {
                                const Pastella::KeyOutput& keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                                Crypto::PublicKey publicKey = keyOutput.key;

                                /* Verify the signature */
                                bool sigValid = Crypto::check_signature(messageHash, publicKey, stakingData.signature);

                                if (sigValid)
                                {
                                    /* Signature is valid! The staker owns this UTXO */
                                    signatureVerified = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    // Failed to get transaction or verify signature
                    // Continue to next input
                    continue;
                }
                catch (...)
                {
                    // Failed to get transaction or verify signature
                    // Continue to next input
                    continue;
                }
            }
        }

        if (!signatureVerified)
        {
            /* No valid signature found for any input
             * This means the staker does NOT own any of the UTXOs being staked
             * REJECT THE TRANSACTION */
            return false;
        }

        // Signature verified successfully
        return true;
    }

    bool StakingValidator::isValidStakingType(uint8_t stakingType)
    {
        return stakingType == Pastella::parameters::staking::STAKING_TX_TYPE;
    }

    /* Utility Functions Implementation */
    uint64_t calculateUnlockTime(uint32_t lockDurationDays, uint64_t currentHeight)
    {
        uint64_t lockPeriodBlocks = (lockDurationDays * 86400ULL) / 30; // 30 seconds per block
        return currentHeight + lockPeriodBlocks;
    }

    uint32_t getRewardRateForLockPeriod(uint32_t lockDurationDays)
    {
        for (size_t i = 0; i < Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS_COUNT; ++i)
        {
            if (lockDurationDays == Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i])
            {
                return Pastella::parameters::staking::ANNUAL_REWARD_RATES[i];
            }
        }

        return 0; // Invalid lock period
    }

    bool isValidLockPeriod(uint32_t lockDurationDays)
    {
        return getRewardRateForLockPeriod(lockDurationDays) != 0;
    }

    /* Phase 2: Stake lifecycle management */
    bool StakingPool::deactivateStakeWithReward(const std::string &stakingTxHash, uint64_t finalRewardAmount)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = activeStakes.find(stakingTxHash);
        if (it == activeStakes.end())
        {
            return false;
        }

        if (!it->second.isActive)
        {
            return true; // Not an error, just already inactive
        }

        // Update accumulated reward to final calculated amount BEFORE deactivation
        it->second.accumulatedReward = finalRewardAmount;
        it->second.accumulatedEarnings = finalRewardAmount; // Keep both in sync

        // Update total staked amount
        totalStakedAmount -= it->second.amount;

        // Mark stake as inactive
        it->second.isActive = false;

        return true;
    }

    bool StakingPool::deactivateStake(const std::string &stakingTxHash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = activeStakes.find(stakingTxHash);
        if (it == activeStakes.end())
        {
            return false;
        }

        if (!it->second.isActive)
        {
            return true; // Not an error, just already inactive
        }

        // Update total staked amount
        totalStakedAmount -= it->second.amount;

        // Mark stake as inactive
        it->second.isActive = false;

        return true;
    }

    bool StakingPool::updateStakeStakerAddress(const std::string &stakingTxHash, const std::string &stakerAddress)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = activeStakes.find(stakingTxHash);
        if (it == activeStakes.end())
        {
            return false;
        }

        it->second.stakerAddress = stakerAddress;
        return true;
    }

    bool StakingPool::reactivateStake(const std::string &stakingTxHash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = activeStakes.find(stakingTxHash);
        if (it == activeStakes.end())
        {
            return false;
        }

        if (it->second.isActive)
        {
            // Already active, nothing to do
            return true;
        }

        // Reactivate the stake
        it->second.isActive = true;
        totalStakedAmount += it->second.amount;

        return true;
    }

    bool StakingPool::reactivateStakesAboveHeight(uint64_t targetHeight)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        uint32_t reactivatedCount = 0;
        for (auto &pair : activeStakes)
        {
            StakingEntry &stake = pair.second;

            // Reactivate if:
            // 1. Stake is currently inactive
            // 2. Stake's unlock time is above the target height (meaning it matured after the target height)
            // 3. Stake was created at or below the target height
            if (!stake.isActive && stake.unlockTime > targetHeight && stake.creationHeight <= targetHeight)
            {
                stake.isActive = true;
                totalStakedAmount += stake.amount;
                reactivatedCount++;
            }
        }

        return reactivatedCount > 0;
    }

    /* Governance voting power calculation methods */

    uint64_t StakingPool::getVotingPower(const std::string &address, uint64_t currentHeight) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        uint64_t totalVotingPower = 0;

        /* Iterate through all active stakes */
        for (const auto &pair : activeStakes)
        {
            const StakingEntry &stake = pair.second;

            /* Only count active stakes (not unlocked) */
            if (!stake.isActive)
            {
                continue;
            }

            /* Check if this stake belongs to the address */
            if (stake.stakerAddress != address)
            {
                continue;
            }

            /* Calculate lock duration multiplier */
            uint64_t multiplier = 1; /* Default 1x */
            if (stake.lockDurationDays >= 360)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_360_DAYS;
            else if (stake.lockDurationDays >= 180)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_180_DAYS;
            else if (stake.lockDurationDays >= 90)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_90_DAYS;
            else if (stake.lockDurationDays >= 30)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_30_DAYS;

            /* Voting power = amount × lock multiplier */
            uint64_t votingPower = stake.amount * multiplier;
            totalVotingPower += votingPower;
        }

        return totalVotingPower;
    }

    bool StakingPool::hasActiveStake(const std::string &address) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        /* Check if address has any active stakes */
        for (const auto &pair : activeStakes)
        {
            const StakingEntry &stake = pair.second;

            /* Only count active stakes */
            if (!stake.isActive)
            {
                continue;
            }

            /* Check if this stake belongs to the address */
            if (stake.stakerAddress == address)
            {
                return true;
            }
        }

        return false;
    }

    std::vector<std::pair<std::string, uint64_t>> StakingPool::getAllVotingPowers(uint64_t currentHeight) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::unordered_map<std::string, uint64_t> addressVotingPowers;

        /* Iterate through all active stakes */
        for (const auto &pair : activeStakes)
        {
            const StakingEntry &stake = pair.second;

            /* Only count active stakes */
            if (!stake.isActive)
            {
                continue;
            }

            /* Calculate lock duration multiplier */
            uint64_t multiplier = 1; /* Default 1x */
            if (stake.lockDurationDays >= 360)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_360_DAYS;
            else if (stake.lockDurationDays >= 180)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_180_DAYS;
            else if (stake.lockDurationDays >= 90)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_90_DAYS;
            else if (stake.lockDurationDays >= 30)
                multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_30_DAYS;

            /* Voting power = amount × lock multiplier */
            uint64_t votingPower = stake.amount * multiplier;

            /* Accumulate voting power for each address */
            addressVotingPowers[stake.stakerAddress] += votingPower;
        }

        /* Convert to vector for return */
        std::vector<std::pair<std::string, uint64_t>> result;
        for (const auto &pair : addressVotingPowers)
        {
            result.push_back(pair);
        }

        return result;
    }
}