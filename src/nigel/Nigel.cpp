// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

////////////////////////
#include <nigel/Nigel.h>
////////////////////////

#include <common/PastellaTools.h>
#include <config/PastellaConfig.h>
#include <pastellacore/CachedBlock.h>
#include <pastellacore/Core.h>
#include <Pastella.h>
#include <errors/ValidateParameters.h>
#include <utilities/Utilities.h>
#include <version.h>

using json = nlohmann::json;

////////////////////////////////
/*   Inline helper methods    */
////////////////////////////////

inline std::shared_ptr<httplib::Client> getClient(
    const std::string daemonHost,
    const uint16_t daemonPort,
    const bool daemonSSL,
    const std::chrono::seconds timeout)
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (daemonSSL)
    {
        return std::make_shared<httplib::SSLClient>(daemonHost.c_str(), daemonPort, timeout.count());
    }
    else
    {
#endif
        return std::make_shared<httplib::Client>(daemonHost.c_str(), daemonPort, timeout.count());
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    }
#endif
}

////////////////////////////////
/* Constructors / Destructors */
////////////////////////////////

Nigel::Nigel(const std::string daemonHost, const uint16_t daemonPort, const bool daemonSSL):
    Nigel(daemonHost, daemonPort, daemonSSL, std::chrono::seconds(10))
{
}

Nigel::Nigel(
    const std::string daemonHost,
    const uint16_t daemonPort,
    const bool daemonSSL,
    const std::chrono::seconds timeout):
    m_timeout(timeout),
    m_daemonHost(daemonHost),
    m_daemonPort(daemonPort),
    m_daemonSSL(daemonSSL)
{
    std::stringstream userAgent;
    userAgent << "Nigel/" << PROJECT_VERSION_LONG;

    m_requestHeaders = {{"User-Agent", userAgent.str()}};
    m_nodeClient = getClient(m_daemonHost, m_daemonPort, m_daemonSSL, m_timeout);
}

Nigel::~Nigel()
{
    stop();
}

//////////////////////
/* Member functions */
//////////////////////

void Nigel::swapNode(const std::string daemonHost, const uint16_t daemonPort, const bool daemonSSL)
{
    stop();

    m_blockCount = Pastella::BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
    m_localDaemonBlockCount = 0;
    m_networkBlockCount = 0;
    m_peerCount = 0;
    m_lastKnownHashrate = 0;
    m_isBlockchainCache = false;
    m_nodeFeeAddress = "";
    m_nodeFeeAmount = 0;
    m_useRawBlocks = true;

    m_daemonHost = daemonHost;
    m_daemonPort = daemonPort;
    m_daemonSSL = daemonSSL;

    m_nodeClient = getClient(m_daemonHost, m_daemonPort, m_daemonSSL, m_timeout);

    init();
}

void Nigel::decreaseRequestedBlockCount()
{
    if (m_blockCount > 1)
    {
        m_blockCount = m_blockCount / 2;
    }
}

void Nigel::resetRequestedBlockCount()
{
    m_blockCount = Pastella::BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
}

std::tuple<bool, std::vector<WalletTypes::WalletBlockInfo>, std::optional<WalletTypes::TopBlock>>
    Nigel::getWalletSyncData(
        const std::vector<Crypto::Hash> blockHashCheckpoints,
        const uint64_t startHeight,
        const uint64_t startTimestamp,
        const bool skipCoinbaseTransactions)
{
    Logger::logger.log("Fetching blocks from the daemon", Logger::DEBUG, {Logger::SYNC, Logger::DAEMON});

    json j = {{"blockHashCheckpoints", blockHashCheckpoints},
              {"startHeight", startHeight},
              {"startTimestamp", startTimestamp},
              {"blockCount", m_blockCount.load()},
              {"skipCoinbaseTransactions", skipCoinbaseTransactions}};

    const std::string endpoint = m_useRawBlocks ? "/getrawblocks" : "/getwalletsyncdata";

    Logger::logger.log(
        "Sending " + endpoint + " request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    const auto res = m_nodeClient->Post(endpoint, m_requestHeaders, j.dump(), "application/json");

    /* Daemon doesn't support /getrawblocks, fall back to /getwalletsyncdata */
    if (res && res->status == 404 && m_useRawBlocks)
    {
        m_useRawBlocks = false;

        return getWalletSyncData(
            blockHashCheckpoints,
            startHeight,
            startTimestamp,
            skipCoinbaseTransactions
        );
    }

    const auto parsedResponse = tryParseJSONResponse(
        res,
        "Failed to fetch blocks from daemon",
        [this, skipCoinbaseTransactions](const nlohmann::json j) {

        std::vector<WalletTypes::WalletBlockInfo> items;

        if (m_useRawBlocks)
        {
            const auto rawBlocks = j.at("items").get<std::vector<Pastella::RawBlock>>();

            for (const auto rawBlock : rawBlocks)
            {
                Pastella::BlockTemplate block;

                fromBinaryArray(block, rawBlock.block);

                WalletTypes::WalletBlockInfo walletBlock;

                Pastella::CachedBlock cachedBlock(block);

                walletBlock.blockHeight = cachedBlock.getBlockIndex();
                walletBlock.blockHash = cachedBlock.getBlockHash();
                walletBlock.blockTimestamp = block.timestamp;

                if (!skipCoinbaseTransactions)
                {
                    walletBlock.coinbaseTransaction = Pastella::Core::getRawCoinbaseTransaction(block.baseTransaction);
                }

                for (const auto &transaction : rawBlock.transactions)
                {
                    walletBlock.transactions.push_back(Pastella::Core::getRawTransaction(transaction));
                }

                items.push_back(walletBlock);
            }
        }
        else
        {
            items = j.at("items").get<std::vector<WalletTypes::WalletBlockInfo>>();
        }

        std::optional<WalletTypes::TopBlock> topBlock;

        if (j.find("synced") != j.end() && j.find("topBlock") != j.end() && j.at("synced").get<bool>())
        {
            topBlock = j.at("topBlock").get<WalletTypes::TopBlock>();
        }

        return std::make_tuple(items, topBlock);
    });

    if (parsedResponse)
    {
        const auto [ items, topBlock ] = *parsedResponse;

        return { true, items, topBlock };
    }

    return { false, {}, std::nullopt };
}

void Nigel::stop()
{
    m_shouldStop = true;

    if (m_backgroundThread.joinable())
    {
        m_backgroundThread.join();
    }
}

void Nigel::init()
{
    m_shouldStop = false;

    /* Get the initial daemon info, and the initial fee info before returning.
       This way the info is always valid, and there's no race on accessing
       the fee info or something */
    getDaemonInfo();

    getFeeInfo();

    /* Now launch the background thread to constantly update the heights etc */
    m_backgroundThread = std::thread(&Nigel::backgroundRefresh, this);
}

bool Nigel::getDaemonInfo()
{
    Logger::logger.log("Updating daemon info", Logger::DEBUG, {Logger::SYNC, Logger::DAEMON});

    Logger::logger.log(
        "Sending /info request to daemon",
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Get("/info", m_requestHeaders);

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to update daemon info", [this](const nlohmann::json j) {
        m_localDaemonBlockCount = j.at("height").get<uint64_t>();

        /* Height returned is one more than the current height - but we
           don't want to overflow is the height returned is zero */
        if (m_localDaemonBlockCount != 0)
        {
            m_localDaemonBlockCount--;
        }

        m_networkBlockCount = j.at("network_height").get<uint64_t>();

        /* Height returned is one more than the current height - but we
           don't want to overflow is the height returned is zero */
        if (m_networkBlockCount != 0)
        {
            m_networkBlockCount--;
        }

        m_peerCount =
            j.at("incoming_connections_count").get<uint64_t>() + j.at("outgoing_connections_count").get<uint64_t>();

        m_lastKnownHashrate = j.at("difficulty").get<uint64_t>() / Pastella::parameters::DIFFICULTY_TARGET;

        /* Look to see if the isCacheApi property exists in the response
           and if so, set the internal value to whatever it found */
        if (j.find("isCacheApi") != j.end())
        {
            m_isBlockchainCache = j.at("isCacheApi").get<bool>();
        }

        return true;
    });

    return parsedResponse.has_value();
}

bool Nigel::getFeeInfo()
{
    Logger::logger.log("Fetching fee info", Logger::DEBUG, {Logger::DAEMON});

    Logger::logger.log(
        "Sending /fee request to daemon",
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Get("/fee", m_requestHeaders);

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to update fee info", [this](const nlohmann::json j) {
        std::string tmpAddress = j.at("address").get<std::string>();

        uint32_t tmpFee = j.at("amount").get<uint32_t>();

        const bool integratedAddressesAllowed = false;

        Error error = validateAddresses({tmpAddress}, integratedAddressesAllowed);

        if (!error)
        {
            m_nodeFeeAddress = tmpAddress;
            m_nodeFeeAmount = tmpFee;
        }

        return true;
    });

    return parsedResponse.has_value();
}

void Nigel::backgroundRefresh()
{
    while (!m_shouldStop)
    {
        getDaemonInfo();

        Utilities::sleepUnlessStopping(std::chrono::seconds(10), m_shouldStop);
    }
}

bool Nigel::isOnline() const
{
    return m_localDaemonBlockCount != 0 || m_networkBlockCount != 0 || m_peerCount != 0 || m_lastKnownHashrate != 0;
}

uint64_t Nigel::localDaemonBlockCount() const
{
    return m_localDaemonBlockCount;
}

uint64_t Nigel::networkBlockCount() const
{
    return m_networkBlockCount;
}

uint64_t Nigel::peerCount() const
{
    return m_peerCount;
}

uint64_t Nigel::hashrate() const
{
    return m_lastKnownHashrate;
}

std::tuple<uint64_t, std::string> Nigel::nodeFee() const
{
    return {m_nodeFeeAmount, m_nodeFeeAddress};
}

std::tuple<std::string, uint16_t, bool> Nigel::nodeAddress() const
{
    return {m_daemonHost, m_daemonPort, m_daemonSSL};
}

bool Nigel::getTransactionsStatus(
    const std::unordered_set<Crypto::Hash> transactionHashes,
    std::unordered_set<Crypto::Hash> &transactionsInPool,
    std::unordered_set<Crypto::Hash> &transactionsInBlock,
    std::unordered_set<Crypto::Hash> &transactionsUnknown) const
{
    json j = {{"transactionHashes", transactionHashes}};

    Logger::logger.log(
        "Sending /get_transactions_status request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/get_transactions_status", m_requestHeaders, j.dump(), "application/json");

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to get transactions status", [&](const nlohmann::json j) {
        transactionsInPool = j.at("transactionsInPool").get<std::unordered_set<Crypto::Hash>>();
        transactionsInBlock = j.at("transactionsInBlock").get<std::unordered_set<Crypto::Hash>>();
        transactionsUnknown = j.at("transactionsUnknown").get<std::unordered_set<Crypto::Hash>>();

        return true;
    });

    return parsedResponse.has_value();
}

std::tuple<bool, std::vector<Pastella::RandomOuts>>
    Nigel::getRandomOutsByAmounts(const std::vector<uint64_t> amounts, const uint64_t requestedOuts) const
{
    json j = {{"amounts", amounts}, {"outs_count", requestedOuts}};

    /* The blockchain cache doesn't call it outs_count
       it calls it mixin */
    if (m_isBlockchainCache)
    {
        j.erase("outs_count");
        j["mixin"] = requestedOuts;

        Logger::logger.log(
            "Sending /randomOutputs request to daemon: " + j.dump(),
            Logger::TRACE,
            { Logger::SYNC, Logger::DAEMON }
        );

        /* We also need to handle the request and response a bit
           differently so we'll do this here */
        auto res = m_nodeClient->Post("/randomOutputs", m_requestHeaders, j.dump(), "application/json");

        const auto parsedResponse = tryParseJSONResponse(res, "Failed to get random outs", [](const nlohmann::json j) {
            return j.get<std::vector<Pastella::RandomOuts>>();
        }, false);

        if (parsedResponse)
        {
            return {true, *parsedResponse};
        }
    }
    else
    {
        Logger::logger.log(
            "Sending /getrandom_outs request to daemon: " + j.dump(),
            Logger::TRACE,
            { Logger::SYNC, Logger::DAEMON }
        );

        auto res = m_nodeClient->Post("/getrandom_outs", m_requestHeaders, j.dump(), "application/json");

        const auto parsedResponse = tryParseJSONResponse(res, "Failed to get random outs", [](const nlohmann::json j) {
            return j.at("outs").get<std::vector<Pastella::RandomOuts>>();
        });

        if (parsedResponse)
        {
            return {true, *parsedResponse};
        }
    }

    return {false, {}};
}

std::tuple<bool, bool, std::string> Nigel::sendTransaction(const Pastella::Transaction tx) const
{
    json j = {{"tx_as_hex", Common::toHex(Pastella::toBinaryArray(tx))}};

    Logger::logger.log(
        "Sending /sendrawtransaction request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/sendrawtransaction", m_requestHeaders, j.dump(), "application/json");

    bool success = false;
    bool connectionError = true;
    std::string error;

    tryParseJSONResponse(res, "Failed to send transaction", [&](const nlohmann::json j) {
        connectionError = false;

        success = j.at("status").get<std::string>() == "OK";

        if (j.find("error") != j.end())
        {
            error = j.at("error").get<std::string>();
        }

        return true;
    }, false);

    return {success, connectionError, error};
}

std::tuple<bool, std::unordered_map<Crypto::Hash, std::vector<uint64_t>>>
    Nigel::getGlobalIndexesForRange(const uint64_t startHeight, const uint64_t endHeight) const
{
    /* GLOBAL INDEX TRACKING REMOVED - Transparent system doesn't use global indexes
     *
     * In a transparent cryptocurrency:
     * - UTXOs are identified by (transactionHash, outputIndex) directly
     * - No ring signature mixing = no need for global output indexes
     * - Wallet sync works without global indexes
     *
     * This method now returns success with empty map to maintain compatibility
     * with wallet sync code that expects this interface. */

    Logger::logger.log(
        "getGlobalIndexesForRange called - NOT requesting from daemon (global indexes removed in transparent system)",
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    /* Return success with empty index map - wallet sync will work without global indexes */
    return {true, {}};
}


std::tuple<bool, std::vector<WalletTypes::StakeInfo>> Nigel::getUserStakesByHashes(
    const std::vector<std::string> &stakingHashes) const
{
    nlohmann::json j;

    j["staking_hashes"] = stakingHashes;

    auto res = m_nodeClient->Post("/getuserstakes", m_requestHeaders, j.dump(), "application/json");

    std::vector<WalletTypes::StakeInfo> result;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to get user stakes by hashes", [&result](const nlohmann::json j) {
        nlohmann::json stakes = j.at("stakes");

        for (const auto &stakeJson : stakes)
        {
            WalletTypes::StakeInfo stakeInfo;

            stakeInfo.stakingTxHash = stakeJson.at("staking_tx_hash").get<Crypto::Hash>();
            stakeInfo.amount = stakeJson.at("amount").get<uint64_t>();
            stakeInfo.unlockTime = stakeJson.at("unlock_time").get<uint64_t>();
            stakeInfo.lockDurationDays = static_cast<uint32_t>(stakeJson.at("lock_duration_days").get<uint64_t>());
            stakeInfo.currentHeight = stakeJson.value("current_height", 0); // Optional field
            stakeInfo.isActive = stakeJson.value("is_active", true); // Default to true
            stakeInfo.pendingRewards = stakeJson.at("accumulated_reward").get<uint64_t>();

            /* Sanity check: if currentHeight is insane, set to reasonable value */
            if (stakeInfo.currentHeight > 100000000) {
                stakeInfo.currentHeight = 0;
            }

            /* Enhanced reward calculation fields */
            stakeInfo.blocksStaked = stakeJson.value("blocks_staked", 0);
            stakeInfo.estDailyReward = stakeJson.value("est_daily_reward", 0);
            stakeInfo.estWeeklyReward = stakeJson.value("est_weekly_reward", 0);
            stakeInfo.estMonthlyReward = stakeJson.value("est_monthly_reward", 0);
            stakeInfo.estYearlyReward = stakeJson.value("est_yearly_reward", 0);
            stakeInfo.accumulatedEarnings = stakeJson.value("accumulated_earnings", 0);

            if (stakeInfo.blocksStaked > 100000) {
                /* If blocks staked is unreasonably high, use API current height */
                stakeInfo.blocksStaked = 0;
            }
            if (stakeInfo.estDailyReward > 10000000000) {
                /* If daily reward is unreasonably high, recalculate using simple method */
                stakeInfo.estDailyReward = (stakeInfo.amount * stakeInfo.dailyRewardRate) / (365 * 100);
            }

            result.push_back(stakeInfo);
        }

        return true;
    });

    return {parsedResponse.has_value(), result};
}

std::tuple<bool, std::string> Nigel::createProposal(
    const std::string title,
    const std::string description,
    const uint8_t proposalType,
    const uint64_t amount,
    const std::string recipientAddress) const
{
    nlohmann::json j;

    j["title"] = title;
    j["description"] = description;
    j["proposal_type"] = proposalType;

    /* Add amount and recipient for treasury proposals */
    if (proposalType == 2) /* PROPOSAL_TYPE_TREASURY */
    {
        j["amount"] = amount;
        j["recipient_address"] = recipientAddress;
    }

    Logger::logger.log(
        "Sending /createproposal request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/createproposal", m_requestHeaders, j.dump(), "application/json");

    std::string result;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to create proposal", [&result](const nlohmann::json json) {
        result = json.value("proposal_id", "0");
        return true;
    });

    return {parsedResponse.has_value(), result};
}

std::tuple<bool, uint64_t> Nigel::getNextProposalId() const
{
    nlohmann::json j;

    Logger::logger.log(
        "Sending /getnextproposalid request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/getnextproposalid", m_requestHeaders, j.dump(), "application/json");

    uint64_t nextProposalId = 0;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to get next proposal ID", [&nextProposalId](const nlohmann::json json) {
        nextProposalId = json.value("next_proposal_id", 0);
        return true;
    });

    return {parsedResponse.has_value(), nextProposalId};
}

std::tuple<bool, std::string> Nigel::castVote(
    const uint64_t proposalId,
    const uint8_t vote) const
{
    nlohmann::json j;

    j["proposal_id"] = proposalId;
    j["vote"] = vote;

    Logger::logger.log(
        "Sending /castvote request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/castvote", m_requestHeaders, j.dump(), "application/json");

    std::string result;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to cast vote", [&result](const nlohmann::json json) {
        result = json.value("message", "Vote cast");
        return true;
    });

    return {parsedResponse.has_value(), result};
}

std::tuple<bool, std::vector<WalletTypes::GovernanceProposal>> Nigel::getGovernanceProposals(
    const bool activeOnly) const
{
    nlohmann::json j;

    if (activeOnly)
    {
        j["active_only"] = true;
    }

    Logger::logger.log(
        "Sending /getproposals request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/getproposals", m_requestHeaders, j.dump(), "application/json");

    std::vector<WalletTypes::GovernanceProposal> result;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to get governance proposals", [&result](const nlohmann::json json) {
        if (json.find("proposals") != json.end())
        {
            nlohmann::json proposals = json["proposals"];

            for (const auto &proposalJson : proposals)
            {
                WalletTypes::GovernanceProposal proposal;

                proposal.proposalId = proposalJson.at("proposalId").get<uint64_t>();
                proposal.title = proposalJson.at("title").get<std::string>();
                proposal.description = proposalJson.at("description").get<std::string>();
                proposal.proposerAddress = proposalJson.value("proposerAddress", "");
                proposal.creationHeight = proposalJson.at("creationHeight").get<uint64_t>();
                proposal.expirationHeight = proposalJson.at("expirationHeight").get<uint64_t>();
                proposal.proposalType = proposalJson.at("proposalType").get<uint8_t>();
                proposal.isActive = proposalJson.at("isActive").get<bool>();
                proposal.votesFor = proposalJson.at("votesFor").get<uint64_t>();
                proposal.votesAgainst = proposalJson.at("votesAgainst").get<uint64_t>();
                proposal.totalVotingPower = proposalJson.at("totalVotingPower").get<uint64_t>();
                proposal.result = proposalJson.at("result").get<std::string>();

                result.push_back(proposal);
            }
        }

        return true;
    });

    return {parsedResponse.has_value(), result};
}

std::tuple<bool, WalletTypes::GovernanceProposal, std::vector<WalletTypes::GovernanceVote>> Nigel::getGovernanceProposal(
    const uint64_t proposalId) const
{
    nlohmann::json j;

    j["proposal_id"] = proposalId;

    Logger::logger.log(
        "Sending /getproposal request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/getproposal", m_requestHeaders, j.dump(), "application/json");

    WalletTypes::GovernanceProposal proposal;
    std::vector<WalletTypes::GovernanceVote> votes;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to get governance proposal", [&proposal, &votes](const nlohmann::json json) {
        if (json.find("proposal") != json.end())
        {
            nlohmann::json proposalJson = json["proposal"];

            proposal.proposalId = proposalJson.at("proposalId").get<uint64_t>();
            proposal.title = proposalJson.at("title").get<std::string>();
            proposal.description = proposalJson.at("description").get<std::string>();
            proposal.proposerAddress = proposalJson.value("proposerAddress", "");
            proposal.creationHeight = proposalJson.at("creationHeight").get<uint64_t>();
            proposal.expirationHeight = proposalJson.at("expirationHeight").get<uint64_t>();
            proposal.proposalType = proposalJson.at("proposalType").get<uint8_t>();
            proposal.isActive = proposalJson.at("isActive").get<bool>();
            proposal.votesFor = proposalJson.at("votesFor").get<uint64_t>();
            proposal.votesAgainst = proposalJson.at("votesAgainst").get<uint64_t>();
            proposal.totalVotingPower = proposalJson.at("totalVotingPower").get<uint64_t>();
            proposal.result = proposalJson.at("result").get<std::string>();
        }

        if (json.find("votes") != json.end())
        {
            nlohmann::json votesJson = json["votes"];

            for (const auto &voteJson : votesJson)
            {
                WalletTypes::GovernanceVote vote;

                vote.proposalId = voteJson.at("proposalId").get<uint64_t>();
                vote.voterAddress = voteJson.at("voterAddress").get<std::string>();
                vote.vote = voteJson.at("vote").get<uint8_t>();
                vote.stakeWeight = voteJson.at("stakeWeight").get<uint64_t>();
                vote.voteHeight = voteJson.at("voteHeight").get<uint64_t>();

                votes.push_back(vote);
            }
        }

        return true;
    });

    return {parsedResponse.has_value(), proposal, votes};
}

std::tuple<bool, uint64_t, std::vector<WalletTypes::StakeInfo>> Nigel::getVotingPower(
    const std::string address) const
{
    nlohmann::json j;

    j["address"] = address;

    Logger::logger.log(
        "Sending /getvotingpower request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/getvotingpower", m_requestHeaders, j.dump(), "application/json");

    uint64_t votingPower = 0;
    std::vector<WalletTypes::StakeInfo> stakes;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to get voting power", [&votingPower, &stakes](const nlohmann::json json) {
        votingPower = json.value("voting_power", 0);

        if (json.find("stakes") != json.end())
        {
            nlohmann::json stakesJson = json["stakes"];

            for (const auto &stakeJson : stakesJson)
            {
                WalletTypes::StakeInfo stakeInfo;

                /* Note: stakingTxHash is not set here since we're using this for voting power display
                   and the hash is not critical for this purpose */
                stakeInfo.amount = stakeJson.at("amount").get<uint64_t>();
                stakeInfo.lockDurationDays = static_cast<uint32_t>(stakeJson.at("lock_duration_days").get<uint64_t>());

                /* Calculate multiplier and voting power for this stake */
                uint64_t multiplier = 1;
                if (stakeInfo.lockDurationDays >= 360)
                    multiplier = 4;
                else if (stakeInfo.lockDurationDays >= 180)
                    multiplier = 3;
                else if (stakeInfo.lockDurationDays >= 90)
                    multiplier = 2;

                stakeInfo.dailyRewardRate = multiplier;

                stakes.push_back(stakeInfo);
            }
        }

        return true;
    });

    return {parsedResponse.has_value(), votingPower, stakes};
}

std::tuple<bool, std::vector<uint8_t>> Nigel::getTransaction(
    const Crypto::Hash &transactionHash) const
{
    json j = {
        {"params", {
            {"hash", Common::podToHex(transactionHash)}
        }}
    };

    Logger::logger.log(
        "Sending /getrawtransaction request to daemon: " + j.dump(),
        Logger::TRACE,
        { Logger::SYNC, Logger::DAEMON }
    );

    auto res = m_nodeClient->Post("/getrawtransaction", m_requestHeaders, j.dump(), "application/json");

    std::vector<uint8_t> result;

    const auto parsedResponse = tryParseJSONResponse(res, "Failed to get raw transaction", [&result](const nlohmann::json j) {
        const std::string txBlob = j.at("result").at("tx_blob").get<std::string>();
        result = Common::fromHex(txBlob);
        return true;
    }, false);  // Set verifyStatus to false since status is nested under "result"

    return {parsedResponse.has_value(), result};
}
