// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

/////////////////////
#include "Currency.h"
/////////////////////

#include <cctype>
#include <common/Base58.h>
#include <common/CheckDifficulty.h>
#include <common/PastellaTools.h>
#include <common/StringTools.h>
#include <common/TransactionExtra.h>
#include <common/Varint.h>
#include <common/int-util.h>
#include <config/Constants.h>
#include <config/WalletConfig.h>
#include <pastellacore/PastellaBasicImpl.h>
#include <pastellacore/PastellaFormatUtils.h>
#include <pastellacore/Difficulty.h>
#include <pastellacore/UpgradeDetector.h>
#include <utilities/Addresses.h>
#include <utilities/String.h>

#undef ERROR

using namespace Logging;
using namespace Common;
using namespace Constants;

namespace Pastella
{
    bool Currency::init()
    {
        if (!generateGenesisBlock())
        {
            logger(ERROR) << "Failed to generate genesis block";
            return false;
        }

        try
        {
            cachedGenesisBlock->getBlockHash();
        }
        catch (std::exception &e)
        {
            logger(ERROR) << "Failed to get genesis block hash: " << e.what();
            return false;
        }

        return true;
    }

    bool Currency::generateGenesisBlock()
    {
        genesisBlockTemplate = BlockTemplate{};

        std::string genesisCoinbaseTxHex = Pastella::parameters::GENESIS_COINBASE_TX_HEX;
        BinaryArray minerTxBlob;

        bool r = fromHex(genesisCoinbaseTxHex, minerTxBlob)
                 && fromBinaryArray(genesisBlockTemplate.baseTransaction, minerTxBlob);

        if (!r)
        {
            logger(ERROR) << "failed to parse coinbase tx from hard coded blob";
            return false;
        }

        genesisBlockTemplate.majorVersion = BLOCK_MAJOR_VERSION_1;
        genesisBlockTemplate.minorVersion = BLOCK_MINOR_VERSION_0;
        genesisBlockTemplate.timestamp = Pastella::parameters::GENESIS_BLOCK_TIMESTAMP;
        genesisBlockTemplate.nonce = 70;

        // miner::find_nonce_for_given_block(bl, 1, 0);
        cachedGenesisBlock.reset(new CachedBlock(genesisBlockTemplate));
        return true;
    }

    size_t Currency::difficultyWindowByBlockVersion(uint8_t blockMajorVersion) const
    {
        return m_difficultyWindow;
    }

    size_t Currency::difficultyLagByBlockVersion(uint8_t blockMajorVersion) const
    {
        return m_difficultyLag;
    }

    size_t Currency::difficultyCutByBlockVersion(uint8_t blockMajorVersion) const
    {
        return m_difficultyCut;
    }

    size_t Currency::difficultyBlocksCountByBlockVersion(uint8_t blockMajorVersion, uint32_t height) const
    {
        if (height >= Pastella::parameters::LWMA_2_DIFFICULTY_BLOCK_INDEX)
        {
            return Pastella::parameters::DIFFICULTY_BLOCKS_COUNT;
        }

        return difficultyWindowByBlockVersion(blockMajorVersion) + difficultyLagByBlockVersion(blockMajorVersion);
    }

    size_t Currency::blockGrantedFullRewardZoneByBlockVersion(uint8_t blockMajorVersion) const
    {
        if (blockMajorVersion == BLOCK_MAJOR_VERSION_2)
        {
            return Pastella::parameters::PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
        }
        else
        {
            return Pastella::parameters::PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
        }
    }

    uint32_t Currency::upgradeHeight(uint8_t majorVersion) const
    {
        if (majorVersion == BLOCK_MAJOR_VERSION_2)
        {
            return m_upgradeHeightV2;
        }
        else
        {
            return static_cast<uint32_t>(-1);
        }
    }

    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
    {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    uint64_t Currency::calculateBlockRewardByHeight(uint32_t height) const
    {
        /* Calculate current halving level */
        uint32_t halvingLevel = 0;
        for (uint32_t i = 0; i < Pastella::parameters::HALVING_HEIGHTS_COUNT; i++) {
            if (height > Pastella::parameters::HALVING_HEIGHTS[i]) {
                halvingLevel++;
            } else {
                break;
            }
        }

        /* Calculate reward with halving applied */
        uint64_t baseReward = Pastella::parameters::BLOCK_REWARD;
        for (uint32_t i = 0; i < halvingLevel; i++) {
            baseReward /= 2;
        }

        /* Minimum reward threshold (stop mining when reward is too small) */
        const uint64_t MIN_REWARD_THRESHOLD = 1;  // 0.00000001 PAS (1 atomic unit)
        if (baseReward < MIN_REWARD_THRESHOLD) {
            return 0;
        }

        return baseReward;
    }

    uint64_t Currency::calculateTotalGeneratedCoins(uint32_t height, uint64_t totalPaidStakingRewards) const
    {
        if (height == 0) return 0;

        uint64_t totalCoins = 0;

        /* Add genesis block reward */
        totalCoins += Pastella::parameters::GENESIS_BLOCK_REWARD;

        /* Calculate rewards for all blocks up to current height */
        for (uint32_t h = 2; h <= height; h++) {
            totalCoins += calculateBlockRewardByHeight(h);
        }

        /* Add staking rewards that have been paid out to matured stakes */
        totalCoins += totalPaidStakingRewards;

        return totalCoins;
    }

    bool Currency::getBlockReward(
        uint8_t blockMajorVersion,
        size_t medianSize,
        size_t currentBlockSize,
        uint64_t alreadyGeneratedCoins,
        uint64_t fee,
        uint64_t &reward,
        int64_t &emissionChange,
        uint32_t height) const
    {
        /* Use manual halving calculation instead of alreadyGeneratedCoins */
        uint64_t baseReward = calculateBlockRewardByHeight(height);

        size_t blockGrantedFullRewardZone = blockGrantedFullRewardZoneByBlockVersion(blockMajorVersion);
        medianSize = std::max(medianSize, blockGrantedFullRewardZone);
        if (currentBlockSize > UINT64_C(2) * medianSize)
        {
            logger(TRACE) << "Block cumulative size is too big: " << currentBlockSize << ", expected less than "
                          << 2 * medianSize;
            return false;
        }

        uint64_t penalizedBaseReward = getPenalizedAmount(baseReward, medianSize, currentBlockSize);
        uint64_t penalizedFee =
            blockMajorVersion >= BLOCK_MAJOR_VERSION_2 ? getPenalizedAmount(fee, medianSize, currentBlockSize) : fee;

        emissionChange = penalizedBaseReward - (fee - penalizedFee);
        reward = penalizedBaseReward + penalizedFee;

        return true;
    }

    size_t Currency::maxBlockCumulativeSize(uint64_t height) const
    {
        assert(height <= std::numeric_limits<uint64_t>::max() / m_maxBlockSizeGrowthSpeedNumerator);
        size_t maxSize = static_cast<size_t>(
            m_maxBlockSizeInitial
            + (height * m_maxBlockSizeGrowthSpeedNumerator) / m_maxBlockSizeGrowthSpeedDenominator);
        assert(maxSize >= m_maxBlockSizeInitial);
        return maxSize;
    }
    bool Currency::constructMinerTx(
        uint8_t blockMajorVersion,
        uint32_t height,
        size_t medianSize,
        uint64_t alreadyGeneratedCoins,
        size_t currentBlockSize,
        uint64_t fee,
        const Crypto::PublicKey &publicKey,
        Transaction &tx,
        const BinaryArray &extraNonce /* = BinaryArray()*/,
        size_t maxOuts /* = 1*/,
        const std::vector<MaturedStakeReward> &stakingRewards /* = {}*/) const
    {
        tx.inputs.clear();
        tx.outputs.clear();
        tx.extra.clear();

        /* TRANSPARENT SYSTEM: Transaction public key for pool support
         * We need the transaction public key so pools can insert their nonce
         * in the extra field. This is NOT used for creating stealth addresses -
         * outputs still go directly to the mining address. */

        KeyPair txkey = generateKeyPair();
        addTransactionPublicKeyToExtra(tx.extra, txkey.publicKey);

        if (!extraNonce.empty())
        {
            if (!addExtraNonceToTransactionExtra(tx.extra, extraNonce))
            {
                return false;
            }
        }

        /* Calculate total staking rewards first */
        uint64_t totalStakingRewards = 0;
        for (const auto &stakingReward : stakingRewards)
        {
            totalStakingRewards += stakingReward.rewardAmount;
        }

        /* Single BaseInput for coinbase transaction */
        BaseInput in;
        in.blockIndex = height;

        uint64_t blockReward;
        int64_t emissionChange;
        if (!getBlockReward(
                blockMajorVersion,
                medianSize,
                currentBlockSize,
                alreadyGeneratedCoins,
                fee,
                blockReward,
                emissionChange,
                height))
        {
            logger(INFO) << "Block is too big";
            return false;
        }

        /* Add single input */
        tx.inputs.push_back(in);

        /* Create single output for mining reward (no denomination splitting) */
        logger(Logging::DEBUGGING) << "[MINER_TX] Creating mining output for amount " << blockReward;

        KeyOutput miningTk;
        miningTk.key = publicKey;  // Direct output!

        TransactionOutput miningOut;
        miningOut.amount = blockReward;
        miningOut.target = miningTk;
        tx.outputs.push_back(miningOut);

        logger(Logging::DEBUGGING) << "[MINER_TX] Mining output key set to: " << Common::podToHex(miningTk.key);

        uint64_t summaryAmounts = blockReward;

        /* Phase 2: Add staking reward output for matured stakes (no additional input) */
        if (totalStakingRewards > 0)
        {
            logger(Logging::INFO) << "Adding staking reward output to coinbase transaction (total: "
                                  << (totalStakingRewards / 100000000.0) << " " << WalletConfig::ticker << ")";

            /* Create single output for all staking rewards (no denomination splitting) */
            AccountPublicAddress rewardAddr;

            /* Use the first staker's address (or miner address if no stakers) */
            if (!stakingRewards.empty() && stakingRewards[0].rewardAmount > 0)
            {
                if (!parseAccountAddressString(stakingRewards[0].stakerAddress, rewardAddr))
                {
                    logger(Logging::ERROR) << "Failed to parse staker address: " << stakingRewards[0].stakerAddress;
                    rewardAddr.publicKey = publicKey;  // Fallback to miner address
                }
            }
            else
            {
                rewardAddr.publicKey = publicKey;
            }

            logger(Logging::DEBUGGING) << "[MINER_TX] Creating staking output for amount " << totalStakingRewards;

            KeyOutput stakingTk;
            stakingTk.key = rewardAddr.publicKey;

            TransactionOutput stakingOut;
            stakingOut.amount = totalStakingRewards;
            stakingOut.target = stakingTk;
            tx.outputs.push_back(stakingOut);

            summaryAmounts += totalStakingRewards;

            logger(Logging::DEBUGGING) << "[MINER_TX] Staking output key set to: " << Common::podToHex(stakingTk.key);
            logger(Logging::INFO) << "Added staking reward output: " << (totalStakingRewards / 100000000.0) << " " << WalletConfig::ticker;
        }

        // Update block reward to include staking rewards for validation
        uint64_t totalBlockReward = blockReward + totalStakingRewards;

        if (!(summaryAmounts == totalBlockReward))
        {
            logger(ERROR) << "Failed to construct miner tx, summaryAmounts = " << summaryAmounts
                                      << " not equal totalBlockReward = " << totalBlockReward
                                      << " (blockReward: " << blockReward << ", stakingRewards: " << totalStakingRewards << ")";
            return false;
        }

        tx.version = CURRENT_TRANSACTION_VERSION;
        // lock
        tx.unlockTime = height + m_minedMoneyUnlockWindow;

        return true;
    }

    std::string Currency::accountAddressAsString(const AccountPublicAddress &accountPublicAddress) const
    {
        return Utilities::getAccountAddressAsStr(m_publicAddressBase58Prefix, accountPublicAddress);
    }

    bool Currency::parseAccountAddressString(const std::string &str, AccountPublicAddress &addr) const
    {
        uint64_t prefix;
        if (!Utilities::parseAccountAddressString(prefix, addr, str))
        {
            return false;
        }

        if (prefix != m_publicAddressBase58Prefix)
        {
            logger(DEBUGGING) << "Wrong address prefix: " << prefix << ", expected " << m_publicAddressBase58Prefix;
            return false;
        }

        return true;
    }

    std::string Currency::formatAmount(uint64_t amount) const
    {
        std::string s = std::to_string(amount);
        if (s.size() < m_numberOfDecimalPlaces + 1)
        {
            s.insert(0, m_numberOfDecimalPlaces + 1 - s.size(), '0');
        }
        s.insert(s.size() - m_numberOfDecimalPlaces, ".");
        return s;
    }

    std::string Currency::formatAmount(int64_t amount) const
    {
        std::string s = formatAmount(static_cast<uint64_t>(std::abs(amount)));

        if (amount < 0)
        {
            s.insert(0, "-");
        }

        return s;
    }

    bool Currency::parseAmount(const std::string &str, uint64_t &amount) const
    {
        std::string strAmount = str;
        Utilities::trim(strAmount);

        size_t pointIndex = strAmount.find_first_of('.');
        size_t fractionSize;
        if (std::string::npos != pointIndex)
        {
            fractionSize = strAmount.size() - pointIndex - 1;
            while (m_numberOfDecimalPlaces < fractionSize && '0' == strAmount.back())
            {
                strAmount.erase(strAmount.size() - 1, 1);
                --fractionSize;
            }
            if (m_numberOfDecimalPlaces < fractionSize)
            {
                return false;
            }
            strAmount.erase(pointIndex, 1);
        }
        else
        {
            fractionSize = 0;
        }

        if (strAmount.empty())
        {
            return false;
        }

        if (!std::all_of(strAmount.begin(), strAmount.end(), ::isdigit))
        {
            return false;
        }

        if (fractionSize < m_numberOfDecimalPlaces)
        {
            strAmount.append(m_numberOfDecimalPlaces - fractionSize, '0');
        }

        return Common::fromString(strAmount, amount);
    }

    uint64_t Currency::getNextDifficulty(
        uint8_t version,
        uint32_t blockIndex,
        std::vector<uint64_t> timestamps,
        std::vector<uint64_t> cumulativeDifficulties) const
    {
        if (blockIndex >= Pastella::parameters::LWMA_2_DIFFICULTY_BLOCK_INDEX)
        {
            return nextDifficultyV5(timestamps, cumulativeDifficulties);
        }
        else
        {
            return nextDifficulty(version, blockIndex, timestamps, cumulativeDifficulties);
        }
    }

    uint64_t Currency::nextDifficulty(
        uint8_t version,
        uint32_t blockIndex,
        std::vector<uint64_t> timestamps,
        std::vector<uint64_t> cumulativeDifficulties) const
    {
        std::vector<uint64_t> timestamps_o(timestamps);
        std::vector<uint64_t> cumulativeDifficulties_o(cumulativeDifficulties);
        size_t c_difficultyWindow = difficultyWindowByBlockVersion(version);
        size_t c_difficultyCut = difficultyCutByBlockVersion(version);

        assert(c_difficultyWindow >= 2);

        if (timestamps.size() > c_difficultyWindow)
        {
            timestamps.resize(c_difficultyWindow);
            cumulativeDifficulties.resize(c_difficultyWindow);
        }

        size_t length = timestamps.size();
        assert(length == cumulativeDifficulties.size());
        assert(length <= c_difficultyWindow);
        if (length <= 1)
        {
            return 1;
        }

        sort(timestamps.begin(), timestamps.end());

        size_t cutBegin, cutEnd;
        assert(2 * c_difficultyCut <= c_difficultyWindow - 2);
        if (length <= c_difficultyWindow - 2 * c_difficultyCut)
        {
            cutBegin = 0;
            cutEnd = length;
        }
        else
        {
            cutBegin = (length - (c_difficultyWindow - 2 * c_difficultyCut) + 1) / 2;
            cutEnd = cutBegin + (c_difficultyWindow - 2 * c_difficultyCut);
        }
        assert(/*cut_begin >= 0 &&*/ cutBegin + 2 <= cutEnd && cutEnd <= length);
        uint64_t timeSpan = timestamps[cutEnd - 1] - timestamps[cutBegin];
        if (timeSpan == 0)
        {
            timeSpan = 1;
        }

        uint64_t totalWork = cumulativeDifficulties[cutEnd - 1] - cumulativeDifficulties[cutBegin];
        assert(totalWork > 0);

        uint64_t low, high;
        low = mul128(totalWork, m_difficultyTarget, &high);
        if (high != 0 || std::numeric_limits<uint64_t>::max() - low < (timeSpan - 1))
        {
            return 0;
        }

        uint8_t c_zawyDifficultyBlockVersion = m_zawyDifficultyBlockVersion;
        if (m_zawyDifficultyV2)
        {
            c_zawyDifficultyBlockVersion = 2;
        }
        if (version >= c_zawyDifficultyBlockVersion && c_zawyDifficultyBlockVersion)
        {
            if (high != 0)
            {
                return 0;
            }
            uint64_t nextDiffZ = low / timeSpan;

            return nextDiffZ;
        }

        if (m_zawyDifficultyBlockIndex && m_zawyDifficultyBlockIndex <= blockIndex)
        {
            if (high != 0)
            {
                return 0;
            }

            /*
              Recalculating 'low' and 'timespan' with hardcoded values:
              DIFFICULTY_CUT=0
              DIFFICULTY_LAG=0
              DIFFICULTY_WINDOW=17
            */
            c_difficultyWindow = 17;
            c_difficultyCut = 0;

            assert(c_difficultyWindow >= 2);

            size_t t_difficultyWindow = c_difficultyWindow;
            if (c_difficultyWindow > timestamps.size())
            {
                t_difficultyWindow = timestamps.size();
            }
            std::vector<uint64_t> timestamps_tmp(timestamps_o.end() - t_difficultyWindow, timestamps_o.end());
            std::vector<uint64_t> cumulativeDifficulties_tmp(
                cumulativeDifficulties_o.end() - t_difficultyWindow, cumulativeDifficulties_o.end());

            length = timestamps_tmp.size();
            assert(length == cumulativeDifficulties_tmp.size());
            assert(length <= c_difficultyWindow);
            if (length <= 1)
            {
                return 1;
            }

            sort(timestamps_tmp.begin(), timestamps_tmp.end());

            assert(2 * c_difficultyCut <= c_difficultyWindow - 2);
            if (length <= c_difficultyWindow - 2 * c_difficultyCut)
            {
                cutBegin = 0;
                cutEnd = length;
            }
            else
            {
                cutBegin = (length - (c_difficultyWindow - 2 * c_difficultyCut) + 1) / 2;
                cutEnd = cutBegin + (c_difficultyWindow - 2 * c_difficultyCut);
            }
            assert(/*cut_begin >= 0 &&*/ cutBegin + 2 <= cutEnd && cutEnd <= length);
            timeSpan = timestamps_tmp[cutEnd - 1] - timestamps_tmp[cutBegin];
            if (timeSpan == 0)
            {
                timeSpan = 1;
            }

            totalWork = cumulativeDifficulties_tmp[cutEnd - 1] - cumulativeDifficulties_tmp[cutBegin];
            assert(totalWork > 0);

            low = mul128(totalWork, m_difficultyTarget, &high);
            if (high != 0 || std::numeric_limits<uint64_t>::max() - low < (timeSpan - 1))
            {
                return 0;
            }
            uint64_t nextDiffZ = low / timeSpan;
            if (nextDiffZ <= 100)
            {
                nextDiffZ = 100;
            }
            return nextDiffZ;
        }

        return (low + timeSpan - 1) / timeSpan; // with version
    }

    bool Currency::checkProofOfWorkV1(const CachedBlock &block, uint64_t currentDifficulty) const
    {
        return check_hash(block.getBlockLongHash(), currentDifficulty);
    }

    bool Currency::checkProofOfWorkV1(const CachedBlock &block, uint64_t currentDifficulty, uint32_t blockHeight) const
    {
        // For RandomX blocks, recalculate the hash with the correct height
        if (block.getBlock().majorVersion >= BLOCK_MAJOR_VERSION_1) {
            const std::vector<uint8_t> &rawHashingBlock = block.getBlockHashingBinaryArray();
            Crypto::Hash heightAwareHash;
            Crypto::randomx_slow_hash_with_height(rawHashingBlock.data(), rawHashingBlock.size(), blockHeight, heightAwareHash);
            return check_hash(heightAwareHash, currentDifficulty);
        }

        // For non-RandomX blocks, use the original method
        return check_hash(block.getBlockLongHash(), currentDifficulty);
    }

    bool Currency::checkProofOfWorkV2(const CachedBlock &cachedBlock, uint64_t currentDifficulty) const
    {
        return false;

        const auto &block = cachedBlock.getBlock();
        if (block.majorVersion < BLOCK_MAJOR_VERSION_2)
        {
            return false;
        }

        if (!check_hash(cachedBlock.getBlockLongHash(), currentDifficulty))
        {
            return false;
        }

        TransactionExtraMergeMiningTag mmTag;
        if (!getMergeMiningTagFromExtra(block.parentBlock.baseTransaction.extra, mmTag))
        {
            logger(ERROR) << "merge mining tag wasn't found in extra of the parent block miner transaction";
            return false;
        }

        if (8 * sizeof(cachedGenesisBlock->getBlockHash()) < block.parentBlock.blockchainBranch.size())
        {
            return false;
        }

        Crypto::Hash auxBlocksMerkleRoot;
        Crypto::tree_hash_from_branch(
            block.parentBlock.blockchainBranch.data(),
            block.parentBlock.blockchainBranch.size(),
            cachedBlock.getAuxiliaryBlockHeaderHash(),
            &cachedGenesisBlock->getBlockHash(),
            auxBlocksMerkleRoot);

        if (auxBlocksMerkleRoot != mmTag.merkleRoot)
        {
            logger(ERROR) << "Aux block hash wasn't found in merkle tree";
            return false;
        }

        return true;
    }

    bool Currency::checkProofOfWork(const CachedBlock &block, uint64_t currentDiffic) const
    {
        switch (block.getBlock().majorVersion)
        {
            case BLOCK_MAJOR_VERSION_1:
            {
                return checkProofOfWorkV1(block, currentDiffic);
            }
            default:
            {
                return checkProofOfWorkV1(block, currentDiffic);
            }
        }

        logger(ERROR) << "Unknown block major version: " << block.getBlock().majorVersion << "."
                                  << block.getBlock().minorVersion;
        return false;
    }

    bool Currency::checkProofOfWork(const CachedBlock &block, uint64_t currentDiffic, uint32_t blockHeight) const
    {
        switch (block.getBlock().majorVersion)
        {
            case BLOCK_MAJOR_VERSION_1:
            {
                return checkProofOfWorkV1(block, currentDiffic, blockHeight);
            }
            default:
            {
                return checkProofOfWorkV1(block, currentDiffic, blockHeight);
            }
        }

        logger(ERROR) << "Unknown block major version: " << block.getBlock().majorVersion << "."
                                  << block.getBlock().minorVersion;
        return false;
    }

    Currency::Currency(Currency &&currency):
        m_maxBlockHeight(currency.m_maxBlockHeight),
        m_maxBlockBlobSize(currency.m_maxBlockBlobSize),
        m_maxTxSize(currency.m_maxTxSize),
        m_publicAddressBase58Prefix(currency.m_publicAddressBase58Prefix),
        m_minedMoneyUnlockWindow(currency.m_minedMoneyUnlockWindow),
        m_timestampCheckWindow(currency.m_timestampCheckWindow),
        m_blockFutureTimeLimit(currency.m_blockFutureTimeLimit),
        m_moneySupply(currency.m_moneySupply),
        m_emissionSpeedFactor(currency.m_emissionSpeedFactor),
        m_rewardBlocksWindow(currency.m_rewardBlocksWindow),
        m_blockGrantedFullRewardZone(currency.m_blockGrantedFullRewardZone),
        m_isBlockexplorer(currency.m_isBlockexplorer),
        m_minerTxBlobReservedSize(currency.m_minerTxBlobReservedSize),
        m_numberOfDecimalPlaces(currency.m_numberOfDecimalPlaces),
        m_coin(currency.m_coin),
        m_mininumFee(currency.m_mininumFee),
        m_defaultDustThreshold(currency.m_defaultDustThreshold),
        m_difficultyTarget(currency.m_difficultyTarget),
        m_difficultyWindow(currency.m_difficultyWindow),
        m_difficultyLag(currency.m_difficultyLag),
        m_difficultyCut(currency.m_difficultyCut),
        m_maxBlockSizeInitial(currency.m_maxBlockSizeInitial),
        m_maxBlockSizeGrowthSpeedNumerator(currency.m_maxBlockSizeGrowthSpeedNumerator),
        m_maxBlockSizeGrowthSpeedDenominator(currency.m_maxBlockSizeGrowthSpeedDenominator),
        m_lockedTxAllowedDeltaSeconds(currency.m_lockedTxAllowedDeltaSeconds),
        m_lockedTxAllowedDeltaBlocks(currency.m_lockedTxAllowedDeltaBlocks),
        m_mempoolTxLiveTime(currency.m_mempoolTxLiveTime),
        m_numberOfPeriodsToForgetTxDeletedFromPool(currency.m_numberOfPeriodsToForgetTxDeletedFromPool),
        m_upgradeHeightV2(currency.m_upgradeHeightV2),
        m_upgradeVotingThreshold(currency.m_upgradeVotingThreshold),
        m_upgradeVotingWindow(currency.m_upgradeVotingWindow),
        m_upgradeWindow(currency.m_upgradeWindow),
        m_blocksFileName(currency.m_blocksFileName),
        m_blockIndexesFileName(currency.m_blockIndexesFileName),
        m_txPoolFileName(currency.m_txPoolFileName),
        m_zawyDifficultyBlockIndex(currency.m_zawyDifficultyBlockIndex),
        m_zawyDifficultyV2(currency.m_zawyDifficultyV2),
        m_zawyDifficultyBlockVersion(currency.m_zawyDifficultyBlockVersion),
        genesisBlockTemplate(std::move(currency.genesisBlockTemplate)),
        cachedGenesisBlock(new CachedBlock(genesisBlockTemplate)),
        logger(currency.logger)
    {
    }

    CurrencyBuilder::CurrencyBuilder(std::shared_ptr<Logging::ILogger> log): m_currency(log)
    {
        maxBlockNumber(parameters::PASTELLA_MAX_BLOCK_NUMBER);
        maxBlockBlobSize(parameters::PASTELLA_MAX_BLOCK_BLOB_SIZE);
        maxTxSize(parameters::PASTELLA_MAX_TX_SIZE);
        publicAddressBase58Prefix(parameters::PASTELLA_PUBLIC_ADDRESS_BASE58_PREFIX);
        minedMoneyUnlockWindow(parameters::PASTELLA_MINED_MONEY_UNLOCK_WINDOW);

        timestampCheckWindow(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);
        blockFutureTimeLimit(parameters::PASTELLA_BLOCK_FUTURE_TIME_LIMIT);

        moneySupply(parameters::MONEY_SUPPLY);
        emissionSpeedFactor(1);

        rewardBlocksWindow(parameters::PASTELLA_REWARD_BLOCKS_WINDOW);
        blockGrantedFullRewardZone(parameters::PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE);
        minerTxBlobReservedSize(parameters::PASTELLA_COINBASE_BLOB_RESERVED_SIZE);

        numberOfDecimalPlaces(parameters::PASTELLA_DISPLAY_DECIMAL_POINT);

        mininumFee(parameters::MINIMUM_FEE);
        defaultDustThreshold(parameters::DEFAULT_DUST_THRESHOLD);

        difficultyTarget(parameters::DIFFICULTY_TARGET);
        difficultyWindow(parameters::DIFFICULTY_WINDOW);
        difficultyLag(parameters::DIFFICULTY_LAG);
        difficultyCut(parameters::DIFFICULTY_CUT);

        maxBlockSizeInitial(parameters::MAX_BLOCK_SIZE_INITIAL);
        maxBlockSizeGrowthSpeedNumerator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR);
        maxBlockSizeGrowthSpeedDenominator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR);

        lockedTxAllowedDeltaSeconds(parameters::PASTELLA_LOCKED_TX_ALLOWED_DELTA_SECONDS);
        lockedTxAllowedDeltaBlocks(parameters::PASTELLA_LOCKED_TX_ALLOWED_DELTA_BLOCKS);

        mempoolTxLiveTime(parameters::PASTELLA_MEMPOOL_TX_LIVETIME);
        mempoolTxFromAltBlockLiveTime(parameters::PASTELLA_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME);
        numberOfPeriodsToForgetTxDeletedFromPool(
            parameters::PASTELLA_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL);

        upgradeHeightV2(parameters::UPGRADE_HEIGHT_V2);
        upgradeVotingThreshold(parameters::UPGRADE_VOTING_THRESHOLD);
        upgradeVotingWindow(parameters::UPGRADE_VOTING_WINDOW);
        upgradeWindow(parameters::UPGRADE_WINDOW);

        blocksFileName(parameters::PASTELLA_BLOCKS_FILENAME);
        blockIndexesFileName(parameters::PASTELLA_BLOCKINDEXES_FILENAME);
        txPoolFileName(parameters::PASTELLA_POOLDATA_FILENAME);

        isBlockexplorer(false);
    }

    Transaction CurrencyBuilder::generateGenesisTransaction()
    {
        /* TRANSPARENT SYSTEM GENESIS TRANSACTION
         * In the original system, the genesis transaction used key derivation
         * to create a direct output to a spend public key without key derivation.
         *
         * This creates a valid genesis transaction for the transparent system where
         * outputs go directly to public keys (Bitcoin-style).
         *
         * The genesis block reward is sent to GENESIS_RECIPIENT_ADDRESS from config. */

        Pastella::Transaction tx;
        tx.version = CURRENT_TRANSACTION_VERSION;
        tx.unlockTime = 0;
        tx.inputs.clear();
        tx.outputs.clear();
        tx.extra.clear();

        /* Create base input (coinbase) */
        BaseInput in;
        in.blockIndex = 0;
        tx.inputs.push_back(in);

        /* Generate transaction public key for extra field */
        KeyPair txkey = generateKeyPair();
        addTransactionPublicKeyToExtra(tx.extra, txkey.publicKey);

        /* Use GENESIS_BLOCK_REWARD (800M PAS) instead of regular block reward (4 PAS) */
        uint64_t genesisReward = Pastella::parameters::GENESIS_BLOCK_REWARD;

        /* Parse the genesis recipient address from config */
        Pastella::AccountPublicAddress genesisRecipient;
        std::string addressStr(Pastella::parameters::GENESIS_RECIPIENT_ADDRESS);

        if (!m_currency.parseAccountAddressString(addressStr, genesisRecipient))
        {
            throw std::runtime_error("Failed to parse GENESIS_RECIPIENT_ADDRESS: " + addressStr);
        }

        /* Extract public key from the address - this is where the genesis coins go */
        Crypto::PublicKey genesisOutputKey = genesisRecipient.publicKey;

        KeyOutput tk;
        tk.key = genesisOutputKey;

        TransactionOutput out;
        out.amount = genesisReward;
        out.target = tk;
        tx.outputs.push_back(out);

        return tx;
    }

    CurrencyBuilder &CurrencyBuilder::emissionSpeedFactor(unsigned int val)
    {
        if (val <= 0 || val > 8 * sizeof(uint64_t))
        {
            throw std::invalid_argument("val at emissionSpeedFactor()");
        }

        m_currency.m_emissionSpeedFactor = val;
        return *this;
    }

    CurrencyBuilder &CurrencyBuilder::numberOfDecimalPlaces(size_t val)
    {
        m_currency.m_numberOfDecimalPlaces = val;
        m_currency.m_coin = 1;
        for (size_t i = 0; i < m_currency.m_numberOfDecimalPlaces; ++i)
        {
            m_currency.m_coin *= 10;
        }

        return *this;
    }

    CurrencyBuilder &CurrencyBuilder::difficultyWindow(size_t val)
    {
        if (val < 2)
        {
            throw std::invalid_argument("val at difficultyWindow()");
        }
        m_currency.m_difficultyWindow = val;
        return *this;
    }

    CurrencyBuilder &CurrencyBuilder::upgradeVotingThreshold(unsigned int val)
    {
        if (val <= 0 || val > 100)
        {
            throw std::invalid_argument("val at upgradeVotingThreshold()");
        }

        m_currency.m_upgradeVotingThreshold = val;
        return *this;
    }

    CurrencyBuilder &CurrencyBuilder::upgradeWindow(uint32_t val)
    {
        if (val <= 0)
        {
            throw std::invalid_argument("val at upgradeWindow()");
        }

        m_currency.m_upgradeWindow = val;
        return *this;
    }

} // namespace Pastella
