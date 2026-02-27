// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

//////////////////////////
#include <rpc/RpcServer.h>
//////////////////////////

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>

#include "version.h"

#include <config/Constants.h>
#include <config/PastellaConfig.h>
#include <crypto/hash-ops.h>  // For RandomX rx_seedheight function
#include <common/PastellaTools.h>
#include <common/TransactionExtra.h>
#include <pastellacore/PastellaFormatUtils.h>
#include <pastellacore/GovernanceSystem.h>
#include <errors/ValidateParameters.h>
#include <logger/Logger.h>
#include <serialization/SerializationTools.h>
#include <utilities/Addresses.h>
#include <utilities/ColouredMsg.h>
#include <utilities/FormatTools.h>
#include <utilities/ParseExtra.h>

RpcServer::RpcServer(
    const uint16_t bindPort,
    const std::string rpcBindIp,
    const std::string corsHeader,
    const std::string feeAddress,
    const uint64_t feeAmount,
    const RpcMode rpcMode,
    const std::shared_ptr<Pastella::Core> core,
    const std::shared_ptr<Pastella::NodeServer> p2p,
    const std::shared_ptr<Pastella::IPastellaProtocolHandler> syncManager):
    m_port(bindPort),
    m_host(rpcBindIp),
    m_corsHeader(corsHeader),
    m_feeAddress(feeAddress),
    m_feeAmount(feeAmount),
    m_rpcMode(rpcMode),
    m_core(core),
    m_p2p(p2p),
    m_syncManager(syncManager)
{
    if (m_feeAddress != "")
    {
        Error error = validateAddresses({m_feeAddress}, false);

        if (error != SUCCESS)
        {
            std::cout << WarningMsg("Fee address given is not valid: " + error.getErrorMessage()) << std::endl;
            exit(1);
        }
    }

    const bool bodyRequired = true;
    const bool bodyNotRequired = false;

    const bool syncRequired = true;
    const bool syncNotRequired = false;

    /* Route the request through our middleware function, before forwarding
       to the specified function */
    const auto router = [this](const auto function, const RpcMode routePermissions, const bool isBodyRequired, const bool syncRequired) {
        return [=](const httplib::Request &req, httplib::Response &res) {
            /* Pass the inputted function with the arguments passed through
               to middleware */
            middleware(
                req,
                res,
                routePermissions,
                isBodyRequired,
                syncRequired,
                std::bind(function, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)
            );
        };
    };

    const auto jsonRpc = [this, router, bodyRequired, bodyNotRequired, syncRequired, syncNotRequired](const auto &req, auto &res) {
        const auto body = getJsonBody(req, res, true);

        if (!body)
        {
            return;
        }

        if (!hasMember(*body, "method"))
        {
            failRequest(400, "Missing JSON parameter: 'method'", res);
            return;
        }

        const auto method = getStringFromJSON(*body, "method");

        if (method == "getblocktemplate")
        {
            router(&RpcServer::getBlockTemplate, RpcMode::Default, bodyRequired, syncRequired)(req, res);
        }
        else if (method == "submitblock")
        {
            router(&RpcServer::submitBlock, RpcMode::Default, bodyRequired, syncRequired)(req, res);
        }
        else if (method == "getblockcount")
        {
            router(&RpcServer::getBlockCount, RpcMode::Default, bodyNotRequired, syncNotRequired)(req, res);
        }
        else if (method == "getlastblockheader")
        {
            router(&RpcServer::getLastBlockHeader, RpcMode::Default, bodyNotRequired, syncNotRequired)(req, res);
        }
        else if (method == "getblockheaderbyhash")
        {
            router(&RpcServer::getBlockHeaderByHash, RpcMode::Default, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "getblockheaderbyheight")
        {
            router(&RpcServer::getBlockHeaderByHeight, RpcMode::Default, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "f_blocks_list_json")
        {
            router(&RpcServer::getBlocksByHeight, RpcMode::BlockExplorerEnabled, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "f_block_json")
        {
            router(&RpcServer::getBlockDetailsByHash, RpcMode::BlockExplorerEnabled, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "f_transaction_json")
        {
            router(&RpcServer::getTransactionDetailsByHash, RpcMode::BlockExplorerEnabled, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "richlist")
        {
            router(&RpcServer::getRichList, RpcMode::BlockExplorerEnabled, bodyNotRequired, syncNotRequired)(req, res);
        }
        else if (method == "getwalletdetails")
        {
            router(&RpcServer::getWalletDetails, RpcMode::BlockExplorerEnabled, bodyRequired, syncNotRequired)(req, res);
        }
        /* UTXO SYSTEM: UTXO query RPC endpoints */
        else if (method == "getutxo")
        {
            router(&RpcServer::getUtxo, RpcMode::BlockExplorerEnabled, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "getutxosfortx")
        {
            router(&RpcServer::getUtxosForTransaction, RpcMode::BlockExplorerEnabled, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "f_on_transactions_pool_json")
        {
            router(&RpcServer::getTransactionsInPool, RpcMode::BlockExplorerEnabled, bodyNotRequired, syncNotRequired)(req, res);
        }
        /* Staking methods via json_rpc */
        else if (method == "getpendingrewards")
        {
            router(&RpcServer::getPendingRewards, RpcMode::Default, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "getuserstakes")
        {
            router(&RpcServer::getUserStakes, RpcMode::Default, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "getallstakes")
        {
            router(&RpcServer::getAllStakes, RpcMode::Default, bodyRequired, syncNotRequired)(req, res);
        }
        /* Governance methods via json_rpc */
        else if (method == "getgovernanceproposals")
        {
            router(&RpcServer::getGovernanceProposals, RpcMode::Default, bodyNotRequired, syncNotRequired)(req, res);
        }
        else if (method == "getproposaldetails")
        {
            router(&RpcServer::getProposalDetails, RpcMode::Default, bodyRequired, syncNotRequired)(req, res);
        }
        else if (method == "createproposal")
        {
            router(&RpcServer::createProposal, RpcMode::Default, bodyRequired, syncRequired)(req, res);
        }
        else if (method == "castvote")
        {
            router(&RpcServer::castVote, RpcMode::Default, bodyRequired, syncRequired)(req, res);
        }
        else if (method == "getvotingpower")
        {
            router(&RpcServer::getVotingPower, RpcMode::Default, bodyRequired, syncNotRequired)(req, res);
        }
        else
        {
            res.status = 404;
        }
    };

    /* Note: /json_rpc is exposed on both GET and POST */
    m_server.Get("/json_rpc", jsonRpc)
            .Get("/info", router(&RpcServer::info, RpcMode::Default, bodyNotRequired, syncNotRequired))
            .Get("/fee", router(&RpcServer::fee, RpcMode::Default, bodyNotRequired, syncNotRequired))
            .Get("/height", router(&RpcServer::height, RpcMode::Default, bodyNotRequired, syncNotRequired))
            .Get("/peers", router(&RpcServer::peers, RpcMode::Default, bodyNotRequired, syncNotRequired))

            .Post("/json_rpc", jsonRpc)
            .Post("/sendrawtransaction", router(&RpcServer::sendTransaction, RpcMode::Default, bodyRequired, syncRequired))
            .Post("/getwalletsyncdata", router(&RpcServer::getWalletSyncData, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/queryblockslite", router(&RpcServer::queryBlocksLite, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/get_transactions_status", router(&RpcServer::getTransactionsStatus, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/get_pool_changes_lite", router(&RpcServer::getPoolChanges, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/queryblocksdetailed", router(&RpcServer::queryBlocksDetailed, RpcMode::AllMethodsEnabled, bodyRequired, syncNotRequired))
            .Post("/getrawblocks", router(&RpcServer::getRawBlocks, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/getrawtransaction", router(&RpcServer::getRawTransaction, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/getutxos", router(&RpcServer::getUtxos, RpcMode::Default, bodyRequired, syncNotRequired))

            /* Staking RPC Endpoints */
            .Get("/getstakingpool", router(&RpcServer::getStakingPoolInfo, RpcMode::Default, bodyNotRequired, syncNotRequired))
            .Post("/getpendingrewards", router(&RpcServer::getPendingRewards, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/getuserstakes", router(&RpcServer::getUserStakes, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/getallstakes", router(&RpcServer::getAllStakes, RpcMode::Default, bodyRequired, syncNotRequired))

            /* Governance RPC Endpoints */
            .Get("/getproposals", router(&RpcServer::getGovernanceProposals, RpcMode::Default, bodyNotRequired, syncNotRequired))
            .Post("/getproposals", router(&RpcServer::getGovernanceProposals, RpcMode::Default, bodyRequired, syncNotRequired))
            .Get("/getproposal", router(&RpcServer::getProposalDetails, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/getproposal", router(&RpcServer::getProposalDetails, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/createproposal", router(&RpcServer::createProposal, RpcMode::Default, bodyRequired, syncRequired))
            .Post("/getnextproposalid", router(&RpcServer::getNextProposalId, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/castvote", router(&RpcServer::castVote, RpcMode::Default, bodyRequired, syncRequired))
            .Get("/getvotingpower", router(&RpcServer::getVotingPower, RpcMode::Default, bodyRequired, syncNotRequired))
            .Post("/getvotingpower", router(&RpcServer::getVotingPower, RpcMode::Default, bodyRequired, syncNotRequired))

            /* Matches everything */
            /* NOTE: Not passing through middleware */
            .Options(".*", [this](auto &req, auto &res) { handleOptions(req, res); });
}

RpcServer::~RpcServer()
{
    stop();
}

void RpcServer::start()
{
    m_serverThread = std::thread(&RpcServer::listen, this);
}

void RpcServer::listen()
{
    const auto listenError = m_server.listen(m_host, m_port);

    if (listenError != httplib::SUCCESS)
    {
        std::cout << WarningMsg("Failed to start RPC server: ")
                  << WarningMsg(httplib::detail::getSocketErrorMessage(listenError)) << std::endl;
        exit(1);
    }
}

void RpcServer::stop()
{
    m_server.stop();

    if (m_serverThread.joinable())
    {
        m_serverThread.join();
    }
}

std::tuple<std::string, uint16_t> RpcServer::getConnectionInfo()
{
    return {m_host, m_port};
}

std::optional<rapidjson::Document> RpcServer::getJsonBody(
    const httplib::Request &req,
    httplib::Response &res,
    const bool bodyRequired)
{
    rapidjson::Document jsonBody;

    if (!bodyRequired)
    {
        /* Some compilers are stupid and can't figure out just `return jsonBody`
         * and we can't construct a std::optional(jsonBody) since the copy
         * constructor is deleted, so we need to std::move */
        return std::optional<rapidjson::Document>(std::move(jsonBody));
    }

    if (jsonBody.Parse(req.body.c_str()).HasParseError())
    {
        std::stringstream stream;

        if (!req.body.empty())
        {
            stream << "Warning: received body is not JSON encoded!\n"
                   << "Key/value parameters are NOT supported.\n"
                   << "Body:\n" << req.body;

            Logger::logger.log(
                stream.str(),
                Logger::INFO,
                { Logger::DAEMON_RPC }
            );
        }

        stream << "Failed to parse request body as JSON";

        failRequest(400, stream.str(), res);

        return std::nullopt;
    }

    return std::optional<rapidjson::Document>(std::move(jsonBody));
}

void RpcServer::middleware(
    const httplib::Request &req,
    httplib::Response &res,
    const RpcMode routePermissions,
    const bool bodyRequired,
    const bool syncRequired,
    std::function<std::tuple<Error, uint16_t>(
        const httplib::Request &req,
        httplib::Response &res,
        const rapidjson::Document &body)> handler)
{
    if (m_corsHeader != "")
    {
        res.set_header("Access-Control-Allow-Origin", m_corsHeader);
    }

    res.set_header("Content-Type", "application/json");

    const auto jsonBody = getJsonBody(req, res, bodyRequired);

    if (!jsonBody)
    {
        return;
    }

    /* Extract method name for logging */
    std::string methodName = "unknown";
    if (jsonBody->HasMember("method") && (*jsonBody)["method"].IsString())
    {
        methodName = (*jsonBody)["method"].GetString();
    }

    Logger::logger.log(
        "[" + req.get_header_value("REMOTE_ADDR") + "] Incoming " + req.method + " request: " + req.path + " (method: " + methodName + "), User-Agent: " + req.get_header_value("User-Agent"),
        Logger::DEBUG,
        { Logger::DAEMON_RPC }
    );

    /* If this route requires higher permissions than we have enabled, then
     * reject the request */
    if (routePermissions > m_rpcMode)
    {
        std::stringstream stream;

        stream << "You do not have permission to access this method. Please "
                  "relaunch your daemon with the --enable-blockexplorer";

        if (routePermissions == RpcMode::AllMethodsEnabled)
        {
            stream << "-detailed";
        }

        stream << " command line option to access this method.";

        failRequest(403, stream.str(), res);

        return;
    }

    if (syncRequired && !m_p2p->get_payload_object().isSynchronized())
    {
        failRequest(200, "Daemon must be synced to process this RPC method call, please retry when synced", res);
        return;
    }

    try
    {
        const auto [error, statusCode] = handler(req, res, *jsonBody);

        if (error)
        {
            rapidjson::StringBuffer sb;
            rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

            writer.StartObject();

            writer.Key("errorCode");
            writer.Uint(error.getErrorCode());

            writer.Key("errorMessage");
            writer.String(error.getErrorMessage());

            writer.EndObject();

            res.body = sb.GetString();
            res.status = 400;
        }
        else
        {
            res.status = statusCode;
        }

        return;
    }
    catch (const std::invalid_argument &e)
    {
        Logger::logger.log(
            "Caught JSON exception, likely missing required json parameter: " + std::string(e.what()),
            Logger::FATAL,
            { Logger::DAEMON_RPC }
        );

        failRequest(400, e.what(), res);
    }
    catch (const std::exception &e)
    {
        std::stringstream error;

        error << "Caught unexpected exception: " << e.what() << " while processing "
              << req.path << " request for User-Agent: " << req.get_header_value("User-Agent");

        // Remove errors as this is not nessesary for production. You as a developer, uncomment this and recompile if needed
        Logger::logger.log(
            error.str(),
            Logger::DEBUG,
            { Logger::DAEMON_RPC }
        );

        if (req.body != "")
        {
            Logger::logger.log(
                "Body: " + req.body,
                Logger::DEBUG,
                { Logger::DAEMON_RPC }
            );
        }

        failRequest(500, "Internal server error: " + std::string(e.what()), res);
    }
}

void RpcServer::failRequest(uint16_t statusCode, std::string body, httplib::Response &res)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("status");
    writer.String("Failed");

    writer.Key("error");
    writer.String(body);

    writer.EndObject();

    res.body = sb.GetString();
    res.status = statusCode;
}

void RpcServer::failJsonRpcRequest(
    const int64_t errorCode,
    const std::string errorMessage,
    httplib::Response &res)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();
    {
        writer.Key("jsonrpc");
        writer.String("2.0");

        writer.Key("error");
        writer.StartObject();
        {
            writer.Key("message");
            writer.String(errorMessage);

            writer.Key("code");
            writer.Int64(errorCode);
        }
        writer.EndObject();
    }
    writer.EndObject();

    res.body = sb.GetString();
    res.status = 200;
}

void RpcServer::handleOptions(const httplib::Request &req, httplib::Response &res) const
{
    Logger::logger.log(
        "Incoming " + req.method + " request: " + req.path,
        Logger::DEBUG,
        { Logger::DAEMON_RPC }
    );

    std::string supported = "OPTIONS, GET, POST";

    if (m_corsHeader == "")
    {
        supported = "";
    }

    if (req.has_header("Access-Control-Request-Method"))
    {
        res.set_header("Access-Control-Allow-Methods", supported);
    }
    else
    {
        res.set_header("Allow", supported);
    }

    if (m_corsHeader != "")
    {
        res.set_header("Access-Control-Allow-Origin", m_corsHeader);
        res.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    }

    res.status = 200;
}

std::tuple<Error, uint16_t> RpcServer::info(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    const uint64_t height = m_core->getTopBlockIndex() + 1;
    const uint64_t networkHeight = std::max(1u, m_syncManager->getBlockchainHeight());
    const auto blockDetails = m_core->getBlockDetails(height - 1);
    const uint64_t difficulty = m_core->getDifficultyForNextBlock();

    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("height");
    writer.Uint64(height);

    writer.Key("difficulty");
    writer.Uint64(difficulty);

    writer.Key("tx_count");
    /* Transaction count without coinbase transactions - one per block, so subtract height */
    writer.Uint64(m_core->getBlockchainTransactionCount() - height);

    writer.Key("tx_pool_size");
    writer.Uint64(m_core->getPoolTransactionCount());

    writer.Key("alt_blocks_count");
    writer.Uint64(m_core->getAlternativeBlockCount());

    uint64_t total_conn = m_p2p->get_connections_count();
    uint64_t outgoing_connections_count = m_p2p->get_outgoing_connections_count();

    writer.Key("outgoing_connections_count");
    writer.Uint64(outgoing_connections_count);

    writer.Key("incoming_connections_count");
    writer.Uint64(total_conn - outgoing_connections_count);

    writer.Key("white_peerlist_size");
    writer.Uint64(m_p2p->getPeerlistManager().get_white_peers_count());

    writer.Key("grey_peerlist_size");
    writer.Uint64(m_p2p->getPeerlistManager().get_gray_peers_count());

    writer.Key("last_known_block_index");
    writer.Uint64(std::max(1u, m_syncManager->getObservedHeight()) - 1);

    writer.Key("network_height");
    writer.Uint64(networkHeight);

    writer.Key("upgrade_heights");
    writer.StartArray();
    {
        for (const uint64_t height : Pastella::parameters::FORK_HEIGHTS)
        {
            writer.Uint64(height);
        }
    }
    writer.EndArray();

    writer.Key("supported_height");
    writer.Uint64(Pastella::parameters::FORK_HEIGHTS_SIZE == 0
        ? 0
        : Pastella::parameters::FORK_HEIGHTS[Pastella::parameters::CURRENT_FORK_INDEX]);

    writer.Key("hashrate");
    writer.Uint64(round(difficulty / Pastella::parameters::DIFFICULTY_TARGET));

    writer.Key("synced");
    writer.Bool(height == networkHeight);

    writer.Key("major_version");
    writer.Uint64(blockDetails.majorVersion);

    writer.Key("minor_version");
    writer.Uint64(blockDetails.minorVersion);

    writer.Key("version");
    writer.String(PROJECT_VERSION);

    writer.Key("status");
    writer.String("OK");

    writer.Key("start_time");
    writer.Uint64(m_core->getStartTime());

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::fee(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("address");
    writer.String(m_feeAddress);

    writer.Key("amount");
    writer.Uint64(m_feeAmount);

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::height(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("height");
    writer.Uint64(m_core->getTopBlockIndex() + 1);

    writer.Key("network_height");
    writer.Uint64(std::max(1u, m_syncManager->getBlockchainHeight()));

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::peers(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    std::list<PeerlistEntry> peers_white;
    std::list<PeerlistEntry> peers_gray;

    m_p2p->getPeerlistManager().get_peerlist_full(peers_gray, peers_white);

    writer.Key("peers");
    writer.StartArray();
    {
        for (const auto &peer : peers_white)
        {
            std::stringstream stream;
            stream << peer.adr;
            writer.String(stream.str());
        }
    }
    writer.EndArray();

    writer.Key("peers_gray");
    writer.StartArray();
    {
        for (const auto &peer : peers_gray)
        {
            std::stringstream stream;
            stream << peer.adr;
            writer.String(stream.str());
        }
    }
    writer.EndArray();

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::sendTransaction(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    std::vector<uint8_t> transaction;

    const std::string rawData = getStringFromJSON(body, "tx_as_hex");

    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    if (!Common::fromHex(rawData, transaction))
    {
        writer.Key("status");
        writer.String("Failed");

        writer.Key("error");
        writer.String("Failed to parse transaction from hex buffer");
    }
    else
    {
        Crypto::Hash transactionHash = Crypto::cn_fast_hash(transaction.data(), transaction.size());

        writer.Key("transactionHash");
        writer.String(Common::podToHex(transactionHash));

        std::stringstream stream;

        stream << "Attempting to add transaction " << transactionHash << " from /sendrawtransaction to pool";

        Logger::logger.log(
            stream.str(),
            Logger::DEBUG,
            { Logger::DAEMON_RPC }
        );

        const auto [success, error] = m_core->addTransactionToPool(transaction);

        if (!success)
        {
            /* Empty stream */
            std::stringstream().swap(stream);

            stream << "Failed to add transaction " << transactionHash << " from /sendrawtransaction to pool: " << error;

            Logger::logger.log(
                stream.str(),
                Logger::INFO,
                { Logger::DAEMON_RPC }
            );

            writer.Key("status");
            writer.String("Failed");

            writer.Key("error");
            writer.String(error);
        }
        else
        {
            m_syncManager->relayTransactions({transaction});

            writer.Key("status");
            writer.String("OK");

            writer.Key("error");
            writer.String("");

        }
    }

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getWalletSyncData(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    std::vector<Crypto::Hash> blockHashCheckpoints;

    if (hasMember(body, "blockHashCheckpoints"))
    {
        for (const auto &jsonHash : getArrayFromJSON(body, "blockHashCheckpoints"))
        {
            std::string hashStr = jsonHash.GetString();

            Crypto::Hash hash;
            Common::podFromHex(hashStr, hash);

            blockHashCheckpoints.push_back(hash);
        }
    }

    const uint64_t startHeight = hasMember(body, "startHeight")
        ? getUint64FromJSON(body, "startHeight")
        : 0;

    const uint64_t startTimestamp = hasMember(body, "startTimestamp")
        ? getUint64FromJSON(body, "startTimestamp")
        : 0;

    const uint64_t blockCount = hasMember(body, "blockCount")
        ? getUint64FromJSON(body, "blockCount")
        : 100;

    const bool skipCoinbaseTransactions = hasMember(body, "skipCoinbaseTransactions")
        ? getBoolFromJSON(body, "skipCoinbaseTransactions")
        : false;

    std::vector<WalletTypes::WalletBlockInfo> walletBlocks;
    std::optional<WalletTypes::TopBlock> topBlockInfo;

    const bool success = m_core->getWalletSyncData(
        blockHashCheckpoints,
        startHeight,
        startTimestamp,
        blockCount,
        skipCoinbaseTransactions,
        walletBlocks,
        topBlockInfo
    );

    if (!success)
    {
        return {SUCCESS, 500};
    }

    writer.Key("items");
    writer.StartArray();
    {
        for (const auto &block : walletBlocks)
        {
            writer.StartObject();

            if (block.coinbaseTransaction)
            {
                writer.Key("coinbaseTX");
                writer.StartObject();
                {
                    writer.Key("outputs");
                    writer.StartArray();
                    {
                        for (const auto &output : block.coinbaseTransaction->keyOutputs)
                        {
                            writer.StartObject();
                            {
                                writer.Key("key");
                                writer.String(Common::podToHex(output.key));

                                writer.Key("amount");
                                writer.Uint64(output.amount);
                            }
                            writer.EndObject();
                        }
                    }
                    writer.EndArray();

                    writer.Key("hash");
                    writer.String(Common::podToHex(block.coinbaseTransaction->hash));

                    writer.Key("txPublicKey");
                    writer.String(Common::podToHex(block.coinbaseTransaction->transactionPublicKey));

                    writer.Key("unlockTime");
                    writer.Uint64(block.coinbaseTransaction->unlockTime);
                }
                writer.EndObject();
            }

            writer.Key("transactions");
            writer.StartArray();
            {
                for (const auto &transaction : block.transactions)
                {
                    writer.StartObject();
                    {
                        writer.Key("outputs");
                        writer.StartArray();
                        {
                            for (const auto &output : transaction.keyOutputs)
                            {
                                writer.StartObject();
                                {
                                    writer.Key("key");
                                    writer.String(Common::podToHex(output.key));

                                    writer.Key("amount");
                                    writer.Uint64(output.amount);
                                }
                                writer.EndObject();
                            }
                        }
                        writer.EndArray();

                        writer.Key("hash");
                        writer.String(Common::podToHex(transaction.hash));

                        writer.Key("txPublicKey");
                        writer.String(Common::podToHex(transaction.transactionPublicKey));

                        writer.Key("unlockTime");
                        writer.Uint64(transaction.unlockTime);



                        writer.Key("inputs");
                        writer.StartArray();
                        {
                            for (const auto &input : transaction.keyInputs)
                            {
                                writer.StartObject();
                                {
                                    writer.Key("amount");
                                    writer.Uint64(input.amount);

                                    writer.Key("key_offsets");
                                    writer.StartArray();
                                    {
                                        for (const auto &offset : input.outputIndexes)
                                        {
                                            writer.Uint64(offset);
                                        }
                                    }
                                    writer.EndArray();

                                    // CRITICAL FIX: Send UTXO reference data for accurate spend detection
                                    // In transparent system, KeyInput explicitly identifies which UTXO is being spent
                                    // BACKWARDS COMPATIBILITY: Only output if fields are valid (non-zero)
                                    // Old transactions may have these fields as zeros if they were created before
                                    // the UTXO reference fields were added to the binary format.
                                    bool hasValidUtxoRef = false;
                                    for (size_t i = 0; i < sizeof(input.transactionHash.data); i++) {
                                        if (input.transactionHash.data[i] != 0) {
                                            hasValidUtxoRef = true;
                                            break;
                                        }
                                    }
                                    if (hasValidUtxoRef || input.outputIndex != 0) {
                                        writer.Key("transactionHash");
                                        writer.String(Common::podToHex(input.transactionHash));

                                        writer.Key("outputIndex");
                                        writer.Uint64(input.outputIndex);
                                    }
                                }
                                writer.EndObject();
                            }
                        }
                        writer.EndArray();
                    }
                    writer.EndObject();
                }
            }
            writer.EndArray();

            /* STAKING TRANSACTIONS: Transactions that are starting to be staked */
            writer.Key("stakingTX");
            writer.StartArray();
            {
                for (const auto &transaction : block.stakingTransactions)
                {
                    writer.StartObject();
                    {
                        writer.Key("outputs");
                        writer.StartArray();
                        {
                            for (const auto &output : transaction.keyOutputs)
                            {
                                writer.StartObject();
                                {
                                    writer.Key("key");
                                    writer.String(Common::podToHex(output.key));

                                    writer.Key("amount");
                                    writer.Uint64(output.amount);
                                }
                                writer.EndObject();
                            }
                        }
                        writer.EndArray();

                        writer.Key("hash");
                        writer.String(Common::podToHex(transaction.hash));

                        writer.Key("txPublicKey");
                        writer.String(Common::podToHex(transaction.transactionPublicKey));

                        writer.Key("unlockTime");
                        writer.Uint64(transaction.unlockTime);

                        writer.Key("inputs");
                        writer.StartArray();
                        {
                            for (const auto &input : transaction.keyInputs)
                            {
                                writer.StartObject();
                                {
                                    writer.Key("amount");
                                    writer.Uint64(input.amount);

                                    writer.Key("key_offsets");
                                    writer.StartArray();
                                    {
                                        for (const auto &offset : input.outputIndexes)
                                        {
                                            writer.Uint64(offset);
                                        }
                                    }
                                    writer.EndArray();

                                    // CRITICAL FIX: Send UTXO reference data for accurate spend detection
                                    // In transparent system, KeyInput explicitly identifies which UTXO is being spent
                                    // BACKWARDS COMPATIBILITY: Only output if fields are valid (non-zero)
                                    // Old transactions may have these fields as zeros if they were created before
                                    // the UTXO reference fields were added to the binary format.
                                    bool hasValidUtxoRef = false;
                                    for (size_t i = 0; i < sizeof(input.transactionHash.data); i++) {
                                        if (input.transactionHash.data[i] != 0) {
                                            hasValidUtxoRef = true;
                                            break;
                                        }
                                    }
                                    if (hasValidUtxoRef || input.outputIndex != 0) {
                                        writer.Key("transactionHash");
                                        writer.String(Common::podToHex(input.transactionHash));

                                        writer.Key("outputIndex");
                                        writer.Uint64(input.outputIndex);
                                    }
                                }
                                writer.EndObject();
                            }
                        }
                        writer.EndArray();
                    }
                    writer.EndObject();
                }
            }
            writer.EndArray();

            writer.Key("blockHeight");
            writer.Uint64(block.blockHeight);

            writer.Key("blockHash");
            writer.String(Common::podToHex(block.blockHash));

            writer.Key("blockTimestamp");
            writer.Uint64(block.blockTimestamp);

            writer.EndObject();
        }
    }
    writer.EndArray();

    if (topBlockInfo)
    {
        writer.Key("topBlock");
        writer.StartObject();
        {
            writer.Key("hash");
            writer.String(Common::podToHex(topBlockInfo->hash));

            writer.Key("height");
            writer.Uint64(topBlockInfo->height);
        }
        writer.EndObject();
    }

    writer.Key("synced");
    writer.Bool(walletBlocks.empty());

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlockTemplate(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");

    writer.StartObject();

    const uint64_t reserveSize = getUint64FromJSON(params, "reserve_size");

    if (reserveSize > 255)
    {
        failJsonRpcRequest(
            -3,
            "Too big reserved size, maximum allowed is 255",
            res
        );

        return {SUCCESS, 200};
    }

    const std::string address = getStringFromJSON(params, "wallet_address");

    Error addressError = validateAddresses({address}, false);

    if (addressError)
    {
        failJsonRpcRequest(
            -4,
            addressError.getErrorMessage(),
            res
        );

        return {SUCCESS, 200};
    }
    const auto publicKey = Utilities::addressToPublicKey(address);
    
    Pastella::BlockTemplate blockTemplate;

    std::vector<uint8_t> blobReserve;
    blobReserve.resize(reserveSize, 0);

    uint64_t difficulty;
    uint32_t height;
    const auto [success, error] = m_core->getBlockTemplate(
        blockTemplate, publicKey, blobReserve, difficulty, height
    );

    if (!success)
    {
        failJsonRpcRequest(
            -5,
            "Failed to create block template: " + error,
            res
        );

        return {SUCCESS, 200};
    }

    std::vector<uint8_t> blockBlob = Pastella::toBinaryArray(blockTemplate);

    const auto transactionPublicKey = Utilities::getTransactionPublicKeyFromExtra(
        blockTemplate.baseTransaction.extra
    );

    uint64_t reservedOffset = 0;

    if (reserveSize > 0)
    {
        /* Find where in the block blob the transaction public key is */
        const auto it = std::search(
            blockBlob.begin(),
            blockBlob.end(),
            std::begin(transactionPublicKey.data),
            std::end(transactionPublicKey.data)
        );

        /* The reserved offset is past the transactionPublicKey, then past
         * the extra nonce tags */
        reservedOffset = (it - blockBlob.begin()) + sizeof(transactionPublicKey) + 2;

        if (reservedOffset + reserveSize > blockBlob.size())
        {
            failJsonRpcRequest(
                -5,
                "Internal error: failed to create block template, not enough space for reserved bytes",
                res
            );

            return {SUCCESS, 200};
        }
    }

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("height");
        writer.Uint(height);

        writer.Key("difficulty");
        writer.Uint64(difficulty);

        writer.Key("reserved_offset");
        writer.Uint64(reservedOffset);

        writer.Key("blocktemplate_blob");
        writer.String(Common::toHex(blockBlob));

        // Add RandomX seed hash information for mining pools
        uint64_t seed_height = Crypto::rx_seedheight(height);
        uint64_t next_seed_height = Crypto::rx_seedheight(height + 1);

        // Get actual block hashes for seed heights
        Crypto::Hash seed_hash;
        Crypto::Hash next_seed_hash;

        try {
            seed_hash = m_core->getBlockHashByIndex(seed_height);
            next_seed_hash = m_core->getBlockHashByIndex(next_seed_height);
        } catch (const std::exception &e) {
            // If we can't get block hash (e.g., for early blocks), use zeros
            memset(&seed_hash, 0, sizeof(Crypto::Hash));
            memset(&next_seed_hash, 0, sizeof(Crypto::Hash));
        }

        writer.Key("seed_hash");
        writer.String(Common::toHex(std::vector<uint8_t>(seed_hash.data, seed_hash.data + Crypto::HASH_SIZE)));

        writer.Key("next_seed_hash");
        writer.String(Common::toHex(std::vector<uint8_t>(next_seed_hash.data, next_seed_hash.data + Crypto::HASH_SIZE)));

        writer.Key("status");
        writer.String("OK");
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::submitBlock(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getArrayFromJSON(body, "params");

    if (params.Size() != 1)
    {
        failJsonRpcRequest(
            -1,
            "You must submit one and only one block blob! (Found " + std::to_string(params.Size()) + ")",
            res
        );

        return {SUCCESS, 200};
    }

    const std::string blockBlob = getStringFromJSONString(params[0]);

    std::vector<uint8_t> rawBlob;

    if (!Common::fromHex(blockBlob, rawBlob))
    {
        failJsonRpcRequest(
            -6,
            "Submitted block blob is not hex!",
            res
        );

        return {SUCCESS, 200};
    }

    const auto submitResult = m_core->submitBlock(rawBlob);

    if (submitResult != Pastella::error::AddBlockErrorCondition::BLOCK_ADDED)
    {
        failJsonRpcRequest(
            -7,
            "Block not accepted",
            res
        );

        return {SUCCESS, 200};
    }

    if (submitResult == Pastella::error::AddBlockErrorCode::ADDED_TO_MAIN
        || submitResult == Pastella::error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED)
    {
        Pastella::NOTIFY_NEW_BLOCK::request newBlockMessage;

        Pastella::BlockTemplate blockTemplate;
        Pastella::fromBinaryArray(blockTemplate, rawBlob);
        newBlockMessage.block = Pastella::RawBlockLegacy(rawBlob, blockTemplate, m_core);
        newBlockMessage.hop = 0;
        newBlockMessage.current_blockchain_height = m_core->getTopBlockIndex() + 1;

        m_syncManager->relayBlock(newBlockMessage);
    }

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlockCount(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("count");
        writer.Uint64(m_core->getTopBlockIndex() + 1);
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getLastBlockHeader(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto height = m_core->getTopBlockIndex();
    const auto hash = m_core->getBlockHashByIndex(height);
    const auto topBlock = m_core->getBlockByHash(hash);
    const auto outputs = topBlock.baseTransaction.outputs;
    const auto extraDetails = m_core->getBlockDetails(hash);

    const uint64_t reward = std::accumulate(outputs.begin(), outputs.end(), 0ull,
        [](const auto acc, const auto out) {
            return acc + out.amount;
        }
    );

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("block_header");
        writer.StartObject();
        {
            writer.Key("major_version");
            writer.Uint64(topBlock.majorVersion);

            writer.Key("minor_version");
            writer.Uint64(topBlock.minorVersion);

            writer.Key("timestamp");
            writer.Uint64(topBlock.timestamp);

            writer.Key("prev_hash");
            writer.String(Common::podToHex(topBlock.previousBlockHash));

            writer.Key("nonce");
            writer.Uint64(topBlock.nonce);

            writer.Key("orphan_status");
            writer.Bool(extraDetails.isAlternative);

            writer.Key("height");
            writer.Uint64(height);

            writer.Key("depth");
            writer.Uint64(0);

            writer.Key("hash");
            writer.String(Common::podToHex(hash));

            writer.Key("difficulty");
            writer.Uint64(m_core->getBlockDifficulty(height));

            writer.Key("reward");
            writer.Uint64(reward);

            writer.Key("num_txes");
            writer.Uint64(extraDetails.transactions.size());

            writer.Key("block_size");
            writer.Uint64(extraDetails.blockSize);
        }
        writer.EndObject();
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlockHeaderByHash(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");
    const auto hashStr = getStringFromJSON(params, "hash");
    const auto topHeight = m_core->getTopBlockIndex();

    Crypto::Hash hash;

    if (!Common::podFromHex(hashStr, hash))
    {
        failJsonRpcRequest(
            -1,
            "Block hash specified is not a valid hex!",
            res
        );

        return {SUCCESS, 200};
    }

    Pastella::BlockTemplate block;

    try
    {
        block = m_core->getBlockByHash(hash);
    }
    catch (const std::runtime_error &)
    {
        failJsonRpcRequest(
            -5,
            "Block hash specified does not exist!",
            res
        );

        return {SUCCESS, 200};
    }

    Pastella::CachedBlock cachedBlock(block);

    const auto height = cachedBlock.getBlockIndex();
    const auto outputs = block.baseTransaction.outputs;
    const auto extraDetails = m_core->getBlockDetails(hash);

    const uint64_t reward = std::accumulate(outputs.begin(), outputs.end(), 0ull,
        [](const auto acc, const auto out) {
            return acc + out.amount;
        }
    );

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("block_header");
        writer.StartObject();
        {
            writer.Key("major_version");
            writer.Uint64(block.majorVersion);

            writer.Key("minor_version");
            writer.Uint64(block.minorVersion);

            writer.Key("timestamp");
            writer.Uint64(block.timestamp);

            writer.Key("prev_hash");
            writer.String(Common::podToHex(block.previousBlockHash));

            writer.Key("nonce");
            writer.Uint64(block.nonce);

            writer.Key("orphan_status");
            writer.Bool(extraDetails.isAlternative);

            writer.Key("height");
            writer.Uint64(height);

            writer.Key("depth");
            writer.Uint64(topHeight - height);

            writer.Key("hash");
            writer.String(Common::podToHex(hash));

            writer.Key("difficulty");
            writer.Uint64(m_core->getBlockDifficulty(height));

            writer.Key("reward");
            writer.Uint64(reward);

            writer.Key("num_txes");
            writer.Uint64(extraDetails.transactions.size());

            writer.Key("block_size");
            writer.Uint64(extraDetails.blockSize);
        }
        writer.EndObject();
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlockHeaderByHeight(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");
    const auto height = getUint64FromJSON(params, "height");
    const auto topHeight = m_core->getTopBlockIndex();

    if (height > topHeight)
    {
        failJsonRpcRequest(
            -2,
            "Requested block header for a height that is higher than the current "
            "blockchain height! Current height: " + std::to_string(topHeight),
            res
        );

        return {SUCCESS, 200};
    }

    const auto hash = m_core->getBlockHashByIndex(height);
    const auto block = m_core->getBlockByHash(hash);

    const auto outputs = block.baseTransaction.outputs;
    const auto extraDetails = m_core->getBlockDetails(hash);

    const uint64_t reward = std::accumulate(outputs.begin(), outputs.end(), 0ull,
        [](const auto acc, const auto out) {
            return acc + out.amount;
        }
    );

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("block_header");
        writer.StartObject();
        {
            writer.Key("major_version");
            writer.Uint64(block.majorVersion);

            writer.Key("minor_version");
            writer.Uint64(block.minorVersion);

            writer.Key("timestamp");
            writer.Uint64(block.timestamp);

            writer.Key("prev_hash");
            writer.String(Common::podToHex(block.previousBlockHash));

            writer.Key("nonce");
            writer.Uint64(block.nonce);

            writer.Key("orphan_status");
            writer.Bool(extraDetails.isAlternative);

            writer.Key("height");
            writer.Uint64(height);

            writer.Key("depth");
            writer.Uint64(topHeight - height);

            writer.Key("hash");
            writer.String(Common::podToHex(hash));

            writer.Key("difficulty");
            writer.Uint64(m_core->getBlockDifficulty(height));

            writer.Key("reward");
            writer.Uint64(reward);

            writer.Key("num_txes");
            writer.Uint64(extraDetails.transactions.size());

            writer.Key("block_size");
            writer.Uint64(extraDetails.blockSize);
        }
        writer.EndObject();
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlocksByHeight(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");
    const auto height = getUint64FromJSON(params, "height");
    const auto topHeight = m_core->getTopBlockIndex();

    if (height > topHeight)
    {
        failJsonRpcRequest(
            -2,
            "Requested block header for a height that is higher than the current "
            "blockchain height! Current height: " + std::to_string(topHeight),
            res
        );

        return {SUCCESS, 200};
    }

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        const uint64_t MAX_BLOCKS_COUNT = 30;
        const uint64_t startHeight = height < MAX_BLOCKS_COUNT ? 0 : height - MAX_BLOCKS_COUNT;

        writer.Key("blocks");
        writer.StartArray();
        {
            for (uint64_t i = height; i >= startHeight; i--)
            {
                writer.StartObject();

                const auto hash = m_core->getBlockHashByIndex(i);
                const auto block = m_core->getBlockByHash(hash);
                const auto extraDetails = m_core->getBlockDetails(hash);

                writer.Key("cumul_size");
                writer.Uint64(extraDetails.blockSize);

                writer.Key("difficulty");
                writer.Uint64(extraDetails.difficulty);

                writer.Key("hash");
                writer.String(Common::podToHex(hash));

                writer.Key("height");
                writer.Uint64(i);

                writer.Key("timestamp");
                writer.Uint64(block.timestamp);

                /* Plus one for coinbase tx */
                writer.Key("tx_count");
                writer.Uint64(block.transactionHashes.size() + 1);

                writer.EndObject();
            }
        }
        writer.EndArray();
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getBlockDetailsByHash(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");
    const auto hashStr = getStringFromJSON(params, "hash");
    const auto topHeight = m_core->getTopBlockIndex();

    Crypto::Hash hash;

    if (hashStr.length() == 64)
    {
        if (!Common::podFromHex(hashStr, hash))
        {
            failJsonRpcRequest(
                -1,
                "Block hash specified is not a valid hex!",
                res
            );

            return {SUCCESS, 200};
        }
    }
    else
    {
        try
        {
            uint64_t height = std::stoull(hashStr);

            hash = m_core->getBlockHashByIndex(height - 1);

            if (hash == Constants::NULL_HASH)
            {
                failJsonRpcRequest(
                    -2,
                    "Requested hash for a height that is higher than the current "
                    "blockchain height! Current height: " + std::to_string(topHeight),
                    res
                );

                return {SUCCESS, 200};
            }
        }
        catch (const std::out_of_range &)
        {
            failJsonRpcRequest(
                -1,
                "Block hash specified is not valid!",
                res
            );

            return {SUCCESS, 200};
        }
        catch (const std::invalid_argument &)
        {
            failJsonRpcRequest(
                -1,
                "Block hash specified is not valid!",
                res
            );

            return {SUCCESS, 200};
        }
    }

    const auto block = m_core->getBlockByHash(hash);
    const auto extraDetails = m_core->getBlockDetails(hash);
    const auto height = Pastella::CachedBlock(block).getBlockIndex();
    const auto outputs = block.baseTransaction.outputs;

    const uint64_t reward = std::accumulate(outputs.begin(), outputs.end(), 0ull,
        [](const auto acc, const auto out) {
            return acc + out.amount;
        }
    );

    const uint64_t blockSizeMedian = std::max(
        extraDetails.sizeMedian,
        static_cast<uint64_t>(
            m_core->getCurrency().blockGrantedFullRewardZoneByBlockVersion(block.majorVersion)
        )
    );

    std::vector<Crypto::Hash> ignore;
    std::vector<std::vector<uint8_t>> transactions;

    m_core->getTransactions(block.transactionHashes, transactions, ignore);

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("block");
        writer.StartObject();
        {
            writer.Key("major_version");
            writer.Uint64(block.majorVersion);

            writer.Key("minor_version");
            writer.Uint64(block.minorVersion);

            writer.Key("timestamp");
            writer.Uint64(block.timestamp);

            writer.Key("prev_hash");
            writer.String(Common::podToHex(block.previousBlockHash));

            writer.Key("nonce");
            writer.Uint64(block.nonce);

            writer.Key("orphan_status");
            writer.Bool(extraDetails.isAlternative);

            writer.Key("height");
            writer.Uint64(height);

            writer.Key("depth");
            writer.Uint64(topHeight - height);

            writer.Key("hash");
            writer.String(Common::podToHex(hash));

            writer.Key("difficulty");
            writer.Uint64(m_core->getBlockDifficulty(height));

            writer.Key("reward");
            writer.Uint64(reward);

            writer.Key("blockSize");
            writer.Uint64(extraDetails.blockSize);

            writer.Key("transactionsCumulativeSize");
            writer.Uint64(extraDetails.transactionsCumulativeSize);

            writer.Key("alreadyGeneratedCoins");
            auto stakingPool = m_core->getStakingPool();
            uint64_t totalPaidStakingRewards = stakingPool ? stakingPool->getTotalPaidStakingRewards() : 0;
            writer.String(std::to_string(m_core->getCurrency().calculateTotalGeneratedCoins(height, totalPaidStakingRewards)));
            
            writer.Key("alreadyGeneratedTransactions");
            writer.Uint64(extraDetails.alreadyGeneratedTransactions);

            writer.Key("sizeMedian");
            writer.Uint64(extraDetails.sizeMedian);

            writer.Key("baseReward");
            writer.Uint64(extraDetails.baseReward);

            writer.Key("penalty");
            writer.Double(extraDetails.penalty);

            writer.Key("effectiveSizeMedian");
            writer.Uint64(blockSizeMedian);

            uint64_t totalFee = 0;

            writer.Key("transactions");
            writer.StartArray();
            {
                /* Coinbase transaction */
                writer.StartObject();
                {
                    const auto txOutputs = block.baseTransaction.outputs;

                    const uint64_t outputAmount = std::accumulate(txOutputs.begin(), txOutputs.end(), 0ull,
                        [](const auto acc, const auto out) {
                            return acc + out.amount;
                        }
                    );

                    writer.Key("hash");
                    writer.String(Common::podToHex(getObjectHash(block.baseTransaction)));

                    writer.Key("fee");
                    writer.Uint64(0);

                    writer.Key("amount_out");
                    writer.Uint64(outputAmount);

                    writer.Key("size");
                    writer.Uint64(getObjectBinarySize(block.baseTransaction));

                    writer.Key("type");
                    writer.String("COINBASE");
                }
                writer.EndObject();

                for (const std::vector<uint8_t> rawTX : transactions)
                {
                    writer.StartObject();
                    {
                        Pastella::Transaction tx;

                        fromBinaryArray(tx, rawTX);

                        const uint64_t outputAmount = std::accumulate(tx.outputs.begin(), tx.outputs.end(), 0ull,
                            [](const auto acc, const auto out) {
                                return acc + out.amount;
                            }
                        );

                        const uint64_t inputAmount = std::accumulate(tx.inputs.begin(), tx.inputs.end(), 0ull,
                            [](const auto acc, const auto in) {
                                if (in.type() == typeid(Pastella::KeyInput))
                                {
                                    return acc + boost::get<Pastella::KeyInput>(in).amount;
                                }

                                return acc;
                            }
                        );

                        const uint64_t fee = inputAmount - outputAmount;

                        writer.Key("hash");
                        writer.String(Common::podToHex(getObjectHash(tx)));

                        writer.Key("fee");
                        writer.Uint64(fee);

                        writer.Key("amount_out");
                        writer.Uint64(outputAmount);

                        writer.Key("size");
                        writer.Uint64(getObjectBinarySize(tx));

                        /* Transaction type: STAKING or regular TRANSFER */
                        const bool isStaking = Pastella::isStakingTransaction(tx.extra);
                        writer.Key("type");
                        writer.String(isStaking ? "STAKING" : "TRANSFER");

                        totalFee += fee;
                    }
                    writer.EndObject();
                }
            }
            writer.EndArray();

            writer.Key("totalFeeAmount");
            writer.Uint64(totalFee);
        }
        writer.EndObject();
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getTransactionDetailsByHash(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");
    const auto hashStr = getStringFromJSON(params, "hash");

    Crypto::Hash hash;

    if (!Common::podFromHex(hashStr, hash))
    {
        failJsonRpcRequest(
            -1,
            "Block hash specified is not a valid hex!",
            res
        );

        return {SUCCESS, 200};
    }

    std::vector<Crypto::Hash> ignore;
    std::vector<std::vector<uint8_t>> rawTXs;
    std::vector<Crypto::Hash> hashes { hash };

    m_core->getTransactions(hashes, rawTXs, ignore);

    if (rawTXs.size() != 1)
    {
        failJsonRpcRequest(
            -1,
            "Block hash specified does not exist!",
            res
        );

        return {SUCCESS, 200};
    }

    Pastella::Transaction transaction;
    Pastella::TransactionDetails txDetails = m_core->getTransactionDetails(hash);

    const uint64_t blockHeight = txDetails.blockIndex;
    const auto blockHash = m_core->getBlockHashByIndex(blockHeight);
    const auto block = m_core->getBlockByHash(blockHash);
    const auto extraDetails = m_core->getBlockDetails(blockHash);

    fromBinaryArray(transaction, rawTXs[0]);

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("block");
        writer.StartObject();
        {
            writer.Key("cumul_size");
            writer.Uint64(extraDetails.blockSize);

            writer.Key("difficulty");
            writer.Uint64(extraDetails.difficulty);

            writer.Key("hash");
            writer.String(Common::podToHex(blockHash));

            writer.Key("height");
            writer.Uint64(blockHeight);

            writer.Key("timestamp");
            writer.Uint64(block.timestamp);

            /* Plus one for coinbase tx */
            writer.Key("tx_count");
            writer.Uint64(block.transactionHashes.size() + 1);
        }
        writer.EndObject();

        writer.Key("tx");
        writer.StartObject();
        {
            writer.Key("extra");
            writer.String(Common::podToHex(transaction.extra));

            writer.Key("unlock_time");
            writer.Uint64(transaction.unlockTime);

            writer.Key("version");
            writer.Uint64(transaction.version);

            writer.Key("vin");
            writer.StartArray();
            {
                size_t inputIndex = 0;
                for (const auto input : transaction.inputs)
                {
                    const auto type = input.type() == typeid(Pastella::BaseInput)
                        ? "ff"
                        : "02";

                    writer.StartObject();
                    {
                        writer.Key("type");
                        writer.String(type);

                        writer.Key("value");
                        writer.StartObject();
                        {
                            if (input.type() == typeid(Pastella::BaseInput))
                            {
                                writer.Key("height");
                                writer.Uint64(boost::get<Pastella::BaseInput>(input).blockIndex);

                                /* Add total generated amount for coinbase inputs */
                                writer.Key("amount");
                                writer.Uint64(txDetails.totalOutputsAmount);
                            }
                            else
                            {
                                const auto keyInput = boost::get<Pastella::KeyInput>(input);


                                writer.Key("amount");
                                writer.Uint64(keyInput.amount);

                                writer.Key("key_offsets");
                                writer.StartArray();
                                {
                                    for (const auto index : keyInput.outputIndexes)
                                    {
                                        writer.Uint(index);
                                    }
                                }
                                writer.EndArray();
                            }
                        }
                        writer.EndObject();

                        /* ADD INPUT ADDRESS FOR TRANSPARENT SYSTEM
                         * Look up the previous transaction to find the output key */
                        if (input.type() == typeid(Pastella::KeyInput) && inputIndex < txDetails.inputs.size())
                        {
                            const auto &keyInputDetails = boost::get<Pastella::KeyInputDetails>(txDetails.inputs[inputIndex]);

                            writer.Key("address");
                            try
                            {
                                Pastella::Transaction prevTransaction;
                                const auto prevTxRaw = m_core->getTransaction(keyInputDetails.output.transactionHash);

                                fromBinaryArray(prevTransaction, prevTxRaw.value());

                                /* Get the output key from the previous transaction */
                                const auto &prevOutput = prevTransaction.outputs[keyInputDetails.output.number];
                                const auto &prevKeyOutput = boost::get<Pastella::KeyOutput>(prevOutput.target);

                                /* Convert output key directly to address */
                                const std::string address = Utilities::publicKeyToAddress(prevKeyOutput.key);
                                writer.String(address);
                            }
                            catch (const std::exception &e)
                            {
                                writer.String("[Unknown]");
                            }
                        }
                    }
                    writer.EndObject();

                    inputIndex++;
                }
            }
            writer.EndArray();

            writer.Key("vout");
            writer.StartArray();
            {
                /* Check if this is a coinbase transaction */
                bool isCoinbase = false;
                if (!transaction.inputs.empty() && transaction.inputs[0].type() == typeid(Pastella::BaseInput))
                {
                    isCoinbase = true;
                }

                /* Reconstruct the exact coinbase decomposition logic */
                std::vector<uint64_t> minerOutputAmounts;
                std::vector<uint64_t> stakerOutputAmounts;
                uint64_t totalStakingRewards = 0; /* Track if block has staking rewards */

                if (isCoinbase)
                {
                    if (blockHeight < Pastella::parameters::staking::STAKING_ENABLE_HEIGHT)
                    {
                        /* Before staking: all outputs are miner rewards */
                        for (const auto &output : transaction.outputs)
                        {
                            minerOutputAmounts.push_back(output.amount);
                        }
                    }
                    else
                    {
                        /* Get the block details to determine base block reward (without staking) */
                        try
                        {
                            auto blockDetails = m_core->getBlockDetails(blockHeight);
                            uint64_t baseBlockReward = blockDetails.reward - blockDetails.totalFeeAmount;

                            /* Subtract total staking rewards from block reward to get miner reward */
                            auto maturedRewards = m_core->getMaturedStakeRewards(blockHeight);
                            totalStakingRewards = 0; /* Use outer variable */
                            for (const auto &maturedReward : maturedRewards)
                            {
                                totalStakingRewards += maturedReward.rewardAmount;
                            }

                            uint64_t minerReward = baseBlockReward - totalStakingRewards;

                            /* Decompose miner reward using the same logic as coinbase construction */
                            const auto &currency = m_core->getCurrency();
                            uint64_t dustThreshold = currency.defaultDustThreshold(blockHeight);

                            Pastella::decompose_amount_into_digits(
                                minerReward,
                                dustThreshold,
                                [&minerOutputAmounts](uint64_t a_chunk) { minerOutputAmounts.push_back(a_chunk); },
                                [&minerOutputAmounts](uint64_t a_dust) { minerOutputAmounts.push_back(a_dust); });

                            /* Decompose each staking reward */
                            for (const auto &maturedReward : maturedRewards)
                            {
                                Pastella::decompose_amount_into_digits(
                                    maturedReward.rewardAmount,
                                    dustThreshold,
                                    [&stakerOutputAmounts](uint64_t a_chunk) { stakerOutputAmounts.push_back(a_chunk); },
                                    [&stakerOutputAmounts](uint64_t a_dust) { stakerOutputAmounts.push_back(a_dust); });
                            }
                        }
                        catch (...)
                        {
                            /* Fallback: if we can't get block details, classify by amount patterns */
                            /* Miner rewards are typically larger amounts, staking rewards are smaller */
                            for (const auto &output : transaction.outputs)
                            {
                                if (output.amount >= 100000000) /* >= 1 PAS likely miner reward */
                                {
                                    minerOutputAmounts.push_back(output.amount);
                                }
                                else
                                {
                                    stakerOutputAmounts.push_back(output.amount);
                                }
                            }
                        }
                    }
                }

                size_t outputIndex = 0;
                for (const auto output : transaction.outputs)
                {
                    std::string outputType = "regular"; /* default for non-coinbase */

                    if (isCoinbase)
                    {
                        /* Determine output type using amount-based heuristics
                         * This works for both old and new coinbase structures */

                        /* Very small amounts (< 0.01 PAS) are typically fee rewards in old blocks */
                        if (output.amount < 1000000) /* Less than 0.01 PAS */
                        {
                            outputType = "fee_reward";
                        }
                        /* For 2-output coinbase transactions: check amounts to determine structure */
                        else if (transaction.outputs.size() == 2)
                        {
                            /* Check if this is old denomination splitting (fee + block reward)
                             * or new structure with staking (block reward + staking reward) */
                            uint64_t amount0 = transaction.outputs[0].amount;
                            uint64_t amount1 = transaction.outputs[1].amount;

                            /* Old denomination splitting: one very small (fee), one large (block reward) */
                            if (amount0 < 1000000 && amount1 >= 100000000)
                            {
                                /* Old structure */
                                if (outputIndex == 0)
                                {
                                    outputType = "fee_reward";
                                }
                                else
                                {
                                    outputType = "miner";
                                }
                            }
                            /* New structure with staking: large block reward + smaller staking reward */
                            else if (amount0 >= 100000000 && amount1 < amount0)
                            {
                                /* New structure with staking */
                                if (outputIndex == 0)
                                {
                                    outputType = "miner";
                                }
                                else
                                {
                                    outputType = "staking_reward";
                                }
                            }
                            else
                            {
                                /* Fallback: try to match using decomposed amounts */
                                auto minerIt = std::find(minerOutputAmounts.begin(), minerOutputAmounts.end(), output.amount);
                                if (minerIt != minerOutputAmounts.end())
                                {
                                    outputType = "miner";
                                    minerOutputAmounts.erase(minerIt);
                                }
                                else
                                {
                                    auto stakerIt = std::find(stakerOutputAmounts.begin(), stakerOutputAmounts.end(), output.amount);
                                    if (stakerIt != stakerOutputAmounts.end())
                                    {
                                        outputType = "staking_reward";
                                        stakerOutputAmounts.erase(stakerIt);
                                    }
                                    else
                                    {
                                        outputType = "miner"; /* Ultimate fallback */
                                    }
                                }
                            }
                        }
                        else
                        {
                            /* Old structure or multiple outputs: use amount matching */
                            auto minerIt = std::find(minerOutputAmounts.begin(), minerOutputAmounts.end(), output.amount);
                            if (minerIt != minerOutputAmounts.end())
                            {
                                outputType = "miner";
                                minerOutputAmounts.erase(minerIt);
                            }
                            else
                            {
                                auto stakerIt = std::find(stakerOutputAmounts.begin(), stakerOutputAmounts.end(), output.amount);
                                if (stakerIt != stakerOutputAmounts.end())
                                {
                                    outputType = "staking_reward";
                                    stakerOutputAmounts.erase(stakerIt);
                                }
                                else
                                {
                                    outputType = "miner"; /* Fallback */
                                }
                            }
                        }
                    }

                    writer.StartObject();
                    {
                        writer.Key("amount");
                        writer.Uint64(output.amount);

                        writer.Key("target");
                        writer.StartObject();
                        {
                            writer.Key("data");
                            writer.StartObject();
                            {
                                writer.Key("key");
                                writer.String(Common::podToHex(boost::get<Pastella::KeyOutput>(output.target).key));
                            }
                            writer.EndObject();

                            /* ADDRESS FOR TRANSPARENT SYSTEM
                             * Output key IS the recipient's public key.
                             * Convert it directly to address format. */
                            writer.Key("type");
                            writer.String("02");

                            writer.Key("address");
                            const auto outputKey = boost::get<Pastella::KeyOutput>(output.target).key;

                            /* Convert output key directly to address */
                            const std::string address = Utilities::publicKeyToAddress(outputKey);
                            writer.String(address);
                        }
                        writer.EndObject();

                        /* Add output type classification for coinbase transactions */
                        if (isCoinbase)
                        {
                            writer.Key("output_type");
                            writer.String(outputType);
                        }

                        /* Increment output index for next iteration */
                        outputIndex++;
                    }
                    writer.EndObject();
                }
            }
            writer.EndArray();
        }
        writer.EndObject();

        writer.Key("txDetails");
        writer.StartObject();
        {
            writer.Key("hash");
            writer.String(Common::podToHex(txDetails.hash));

            writer.Key("amount_out");
            writer.Uint64(txDetails.totalOutputsAmount);

            writer.Key("fee");
            writer.Uint64(txDetails.fee);

            writer.Key("size");
            writer.Uint64(txDetails.size);

            /* Transaction type classification */
            writer.Key("tx_types");
            writer.StartArray();
            {
                std::set<std::string> txTypes;

                /* Check if it's a coinbase transaction */
                bool isCoinbase = !transaction.inputs.empty() && transaction.inputs[0].type() == typeid(Pastella::BaseInput);
                if (isCoinbase)
                {
                    txTypes.insert("miner");

                    /* Check if this coinbase has staking rewards */
                    if (blockHeight >= Pastella::parameters::staking::STAKING_ENABLE_HEIGHT)
                    {
                        auto maturedRewards = m_core->getMaturedStakeRewards(blockHeight);
                        if (!maturedRewards.empty())
                        {
                            txTypes.insert("staking_reward");
                        }
                    }
                }
                else
                {
                    /* Not a coinbase transaction - check if it's a staking transaction first */
                    if (Pastella::isStakingTransaction(transaction.extra))
                    {
                        txTypes.insert("staking");
                    }
                    else
                    {
                        /* Regular transfer transaction */
                        txTypes.insert("regular");
                    }
                }

                /* Write all transaction types to the array */
                for (const auto &type : txTypes)
                {
                    writer.String(type);
                }
            }
            writer.EndArray();
        }
        writer.EndObject();
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getRichList(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    /* Get count parameter (default: 100 for top 100) */
    size_t count = 100;

    if (body.HasMember("params"))
    {
        const auto params = getObjectFromJSON(body, "params");

        if (params.HasMember("count") && params["count"].IsUint64())
        {
            count = params["count"].GetUint64();
            if (count == 0 || count > 1000)
            {
                /* Limit to reasonable range */
                count = std::min(count, (size_t)1000);
            }
        }
    }

    writer.StartObject();

    try
    {
        /* Get rich list from core */
        const auto richList = m_core->getRichList(count);

        writer.Key("status");
        writer.String("OK");

        writer.Key("count");
        writer.Uint64(richList.size());

        writer.Key("richlist");
        writer.StartArray();
        {
            for (const auto &entry : richList)
            {
                writer.StartObject();
                {
                    writer.Key("address");
                    writer.String(entry.address);

                    writer.Key("balance");
                    writer.Uint64(entry.balance);

                    writer.Key("balance_formatted");
                    std::stringstream balanceStr;
                    balanceStr << std::fixed << std::setprecision(8) << (entry.balance / 100000000.0);
                    writer.String(balanceStr.str());

                    writer.Key("percentage");
                    writer.Double(entry.percentage);

                    writer.Key("first_tx_timestamp");
                    writer.Uint64(entry.firstTxTimestamp);

                    /* Convert timestamp to readable date */
                    writer.Key("first_tx_date");
                    if (entry.firstTxTimestamp > 0)
                    {
                        std::time_t firstTime = static_cast<std::time_t>(entry.firstTxTimestamp);
                        std::tm firstTm;
#ifdef _WIN32
                        gmtime_s(&firstTm, &firstTime);
#else
                        gmtime_r(&firstTime, &firstTm);
#endif
                        char firstDateBuffer[80];
                        std::strftime(firstDateBuffer, sizeof(firstDateBuffer), "%Y-%m-%d %H:%M:%S UTC", &firstTm);
                        writer.String(firstDateBuffer);
                    }
                    else
                    {
                        writer.String("Unknown");
                    }

                    writer.Key("last_tx_timestamp");
                    writer.Uint64(entry.lastTxTimestamp);

                    /* Convert timestamp to readable date */
                    writer.Key("last_tx_date");
                    if (entry.lastTxTimestamp > 0)
                    {
                        std::time_t lastTime = static_cast<std::time_t>(entry.lastTxTimestamp);
                        std::tm lastTm;
#ifdef _WIN32
                        gmtime_s(&lastTm, &lastTime);
#else
                        gmtime_r(&lastTime, &lastTm);
#endif
                        char lastDateBuffer[80];
                        std::strftime(lastDateBuffer, sizeof(lastDateBuffer), "%Y-%m-%d %H:%M:%S UTC", &lastTm);
                        writer.String(lastDateBuffer);
                    }
                    else
                    {
                        writer.String("Unknown");
                    }
                }
                writer.EndObject();
            }
        }
        writer.EndArray();
    }
    catch (const std::exception &e)
    {
        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String(std::string("Failed to get rich list: ") + e.what());
    }

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getWalletDetails(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    /* Get parameters */
    size_t limit = 100;
    size_t page = 0;
    std::string address;

    /* Get params object */
    const auto params = getObjectFromJSON(body, "params");

    /* Get address (required) */
    if (params.HasMember("address") && params["address"].IsString())
    {
        address = params["address"].GetString();
    }
    else
    {
        writer.StartObject();

        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String("Address parameter is required");

        writer.EndObject();

        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    /* Get optional limit parameter */
    if (params.HasMember("limit") && params["limit"].IsUint64())
    {
        limit = params["limit"].GetUint64();
        if (limit == 0 || limit > 1000)
        {
            /* Limit to reasonable range */
            limit = std::min(limit, (size_t)1000);
        }
    }

    /* Get optional page parameter */
    if (params.HasMember("page") && params["page"].IsUint64())
    {
        page = params["page"].GetUint64();
    }

    writer.StartObject();

    try
    {
        /* Get wallet details from core */
        const auto details = m_core->getWalletDetails(address, limit, page);

        writer.Key("status");
        writer.String("OK");

        writer.Key("address");
        writer.String(details.address);

        writer.Key("total_balance");
        writer.Uint64(details.totalBalance);

        writer.Key("total_balance_formatted");
        std::stringstream balanceStr;
        balanceStr << std::fixed << std::setprecision(8) << (details.totalBalance / 100000000.0);
        writer.String(balanceStr.str());

        writer.Key("total_incoming");
        writer.Uint64(details.totalIncoming);

        writer.Key("total_incoming_formatted");
        std::stringstream incomingStr;
        incomingStr << std::fixed << std::setprecision(8) << (details.totalIncoming / 100000000.0);
        writer.String(incomingStr.str());

        writer.Key("total_outgoing");
        writer.Uint64(details.totalOutgoing);

        writer.Key("total_outgoing_formatted");
        std::stringstream outgoingStr;
        outgoingStr << std::fixed << std::setprecision(8) << (details.totalOutgoing / 100000000.0);
        writer.String(outgoingStr.str());

        writer.Key("total_incoming_staking_rewards");
        writer.Uint64(details.totalIncomingStakingRewards);

        writer.Key("total_incoming_staking_rewards_formatted");
        std::stringstream stakingRewardsStr;
        stakingRewardsStr << std::fixed << std::setprecision(8) << (details.totalIncomingStakingRewards / 100000000.0);
        writer.String(stakingRewardsStr.str());

        writer.Key("total_outgoing_stakes");
        writer.Uint64(details.totalOutgoingStakes);

        writer.Key("total_outgoing_stakes_formatted");
        std::stringstream stakesStr;
        stakesStr << std::fixed << std::setprecision(8) << (details.totalOutgoingStakes / 100000000.0);
        writer.String(stakesStr.str());

        writer.Key("total_transactions");
        writer.Uint64(details.totalTransactions);

        writer.Key("first_tx_timestamp");
        writer.Uint64(details.firstTxTimestamp);

        writer.Key("first_tx_date");
        if (details.firstTxTimestamp > 0 && details.firstTxTimestamp != UINT64_MAX)
        {
            std::time_t firstTime = static_cast<std::time_t>(details.firstTxTimestamp);
            std::tm firstTm;
#ifdef _WIN32
            gmtime_s(&firstTm, &firstTime);
#else
            gmtime_r(&firstTime, &firstTm);
#endif
            char firstDateBuffer[80];
            std::strftime(firstDateBuffer, sizeof(firstDateBuffer), "%Y-%m-%d %H:%M:%S UTC", &firstTm);
            writer.String(firstDateBuffer);
        }
        else
        {
            writer.String("Unknown");
        }

        writer.Key("last_tx_timestamp");
        writer.Uint64(details.lastTxTimestamp);

        writer.Key("last_tx_date");
        if (details.lastTxTimestamp > 0)
        {
            std::time_t lastTime = static_cast<std::time_t>(details.lastTxTimestamp);
            std::tm lastTm;
#ifdef _WIN32
            gmtime_s(&lastTm, &lastTime);
#else
            gmtime_r(&lastTime, &lastTm);
#endif
            char lastDateBuffer[80];
            std::strftime(lastDateBuffer, sizeof(lastDateBuffer), "%Y-%m-%d %H:%M:%S UTC", &lastTm);
            writer.String(lastDateBuffer);
        }
        else
        {
            writer.String("Unknown");
        }

        writer.Key("transactions");
        writer.StartArray();
        {
            for (const auto &tx : details.transactions)
            {
                writer.StartObject();
                {
                    writer.Key("tx_hash");
                    writer.String(Common::podToHex(tx.transactionHash));

                    writer.Key("block_number");
                    writer.Uint64(tx.blockNumber);

                    writer.Key("block_hash");
                    writer.String(Common::podToHex(tx.blockHash));

                    writer.Key("amount");
                    writer.Uint64(tx.amount);

                    writer.Key("amount_formatted");
                    std::stringstream amountStr;
                    amountStr << std::fixed << std::setprecision(8) << (tx.amount / 100000000.0);
                    writer.String(amountStr.str());

                    writer.Key("type");
                    switch (tx.type)
                    {
                        case Pastella::TransactionType::MINING:
                            writer.String("MINING");
                            break;
                        case Pastella::TransactionType::STAKE_REWARD:
                            writer.String("STAKE_REWARD");
                            break;
                        case Pastella::TransactionType::INCOMING:
                            writer.String("INCOMING");
                            break;
                        case Pastella::TransactionType::OUTGOING:
                            writer.String("OUTGOING");
                            break;
                        case Pastella::TransactionType::STAKE_DEPOSIT:
                            writer.String("STAKE_DEPOSIT");
                            break;
                        case Pastella::TransactionType::STAKE_UNLOCK:
                            writer.String("STAKE_UNLOCK");
                            break;
                        default:
                            writer.String("UNKNOWN");
                            break;
                    }

                    writer.Key("timestamp");
                    writer.Uint64(tx.timestamp);

                    writer.Key("date");
                    if (tx.timestamp > 0)
                    {
                        std::time_t txTime = static_cast<std::time_t>(tx.timestamp);
                        std::tm txTm;
#ifdef _WIN32
                        gmtime_s(&txTm, &txTime);
#else
                        gmtime_r(&txTime, &txTm);
#endif
                        char txDateBuffer[80];
                        std::strftime(txDateBuffer, sizeof(txDateBuffer), "%Y-%m-%d %H:%M:%S UTC", &txTm);
                        writer.String(txDateBuffer);
                    }
                    else
                    {
                        writer.String("Unknown");
                    }

                    writer.Key("unlock_time");
                    writer.Uint64(tx.unlockTime);

                    writer.Key("fee");
                    writer.Uint64(tx.fee);

                    writer.Key("fee_formatted");
                    std::stringstream feeStr;
                    feeStr << std::fixed << std::setprecision(8) << (tx.fee / 100000000.0);
                    writer.String(feeStr.str());

                    writer.Key("from");
                    writer.StartArray();
                    for (const auto &addr : tx.fromAddresses)
                    {
                        writer.String(addr);
                    }
                    writer.EndArray();

                    writer.Key("to");
                    writer.StartArray();
                    for (const auto &addr : tx.toAddresses)
                    {
                        writer.String(addr);
                    }
                    writer.EndArray();
                }
                writer.EndObject();
            }
        }
        writer.EndArray();

        /* Pagination info */
        writer.Key("pagination");
        writer.StartObject();
        {
            writer.Key("limit");
            writer.Uint64(limit);

            writer.Key("page");
            writer.Uint64(page);

            writer.Key("total_count");
            writer.Uint64(details.totalTransactions);

            writer.Key("returned_count");
            writer.Uint64(details.transactions.size());

            writer.Key("total_pages");
            if (limit > 0)
            {
                writer.Uint64((details.totalTransactions + limit - 1) / limit);
            }
            else
            {
                writer.Uint64(1);
            }
        }
        writer.EndObject();
    }
    catch (const std::exception &e)
    {
        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String(std::string("Failed to get wallet details: ") + e.what());
    }

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getRawTransaction(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    const auto params = getObjectFromJSON(body, "params");
    const auto hashStr = getStringFromJSON(params, "hash");

    Crypto::Hash hash;

    if (!Common::podFromHex(hashStr, hash))
    {
        failJsonRpcRequest(
            -1,
            "Transaction hash specified is not a valid hex!",
            res
        );

        return {SUCCESS, 200};
    }

    std::vector<Crypto::Hash> ignore;
    std::vector<std::vector<uint8_t>> rawTXs;
    std::vector<Crypto::Hash> hashes { hash };

    m_core->getTransactions(hashes, rawTXs, ignore);

    if (rawTXs.empty())
    {
        failJsonRpcRequest(
            -1,
            "Transaction not found",
            res
        );

        return {SUCCESS, 200};
    }

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("tx_blob");
        writer.String(Common::toHex(rawTXs[0]));
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getUtxos(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    /* Parse request parameters */
    const auto params = getObjectFromJSON(body, "params");
    const uint64_t page = getUint64FromJSON(params, "page");
    const uint64_t limit = getUint64FromJSON(params, "limit");

    /* Query UTXOs from blockchain */
    const auto [success, utxos, totalUTXOs] = m_core->getUTXOs(page, limit);

    if (!success)
    {
        failJsonRpcRequest(
            -1,
            "Failed to query UTXOs from database",
            res
        );

        return {SUCCESS, 200};
    }

    /* Calculate pagination info */
    const uint64_t actualLimit = (limit == 0 || limit > 1000) ? 100 : limit;
    const uint64_t totalPages = (totalUTXOs + actualLimit - 1) / actualLimit;

    /* Build response */
    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("utxos");
        writer.StartArray();
        {
            for (const auto &utxo : utxos)
            {
                writer.StartObject();

                /* Create UTXO key identifier: txHash:outputIndex */
                std::stringstream utxoKey;
                utxoKey << Common::podToHex(utxo.transactionHash) << ":" << utxo.outputIndex;

                writer.Key("utxoKey");
                writer.String(utxoKey.str());

                writer.Key("transactionHash");
                writer.String(Common::podToHex(utxo.transactionHash));

                writer.Key("outputIndex");
                writer.Uint(utxo.outputIndex);

                writer.Key("amount");
                writer.Uint64(utxo.amount);

                writer.Key("publicKey");
                writer.String(Common::podToHex(utxo.publicKey));

                writer.Key("blockIndex");
                writer.Uint(utxo.blockIndex);

                writer.Key("spent");
                writer.Bool(utxo.spent);

                writer.Key("spentBlockIndex");
                writer.Uint(utxo.spentBlockIndex);

                writer.EndObject();
            }
        }
        writer.EndArray();

        writer.Key("totalUTXOs");
        writer.Uint64(totalUTXOs);

        writer.Key("totalPages");
        writer.Uint64(totalPages);

        writer.Key("currentPage");
        writer.Uint64(page);
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getTransactionsInPool(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    writer.Key("jsonrpc");
    writer.String("2.0");

    writer.Key("result");
    writer.StartObject();
    {
        writer.Key("status");
        writer.String("OK");

        writer.Key("transactions");
        writer.StartArray();
        {
            for (const auto tx : m_core->getPoolTransactions())
            {
                writer.StartObject();

                const uint64_t outputAmount = std::accumulate(tx.outputs.begin(), tx.outputs.end(), 0ull,
                    [](const auto acc, const auto out) {
                        return acc + out.amount;
                    }
                );

                const uint64_t inputAmount = std::accumulate(tx.inputs.begin(), tx.inputs.end(), 0ull,
                    [](const auto acc, const auto in) {
                        if (in.type() == typeid(Pastella::KeyInput))
                        {
                            return acc + boost::get<Pastella::KeyInput>(in).amount;
                        }

                        return acc;
                    }
                );

                const uint64_t fee = inputAmount - outputAmount;

                /* Basic transaction info */
                writer.Key("hash");
                writer.String(Common::podToHex(getObjectHash(tx)));

                writer.Key("fee");
                writer.Uint64(fee);

                writer.Key("fee_formatted");
                std::stringstream feeStr;
                feeStr << std::fixed << std::setprecision(8) << (fee / 100000000.0);
                writer.String(feeStr.str());

                writer.Key("amount_in");
                writer.Uint64(inputAmount);

                writer.Key("amount_in_formatted");
                std::stringstream amountInStr;
                amountInStr << std::fixed << std::setprecision(8) << (inputAmount / 100000000.0);
                writer.String(amountInStr.str());

                writer.Key("amount_out");
                writer.Uint64(outputAmount);

                writer.Key("amount_out_formatted");
                std::stringstream amountOutStr;
                amountOutStr << std::fixed << std::setprecision(8) << (outputAmount / 100000000.0);
                writer.String(amountOutStr.str());

                writer.Key("size");
                writer.Uint64(getObjectBinarySize(tx));

                writer.Key("unlock_time");
                writer.Uint64(tx.unlockTime);

                /* TRANSPARENT SYSTEM: Transaction type */
                const bool isStaking = Pastella::isStakingTransaction(tx.extra);
                writer.Key("type");
                writer.String(isStaking ? "STAKING" : "TRANSFER");

                /* TRANSPARENT SYSTEM: Outputs with addresses derived from keys */
                writer.Key("outputs");
                writer.StartArray();
                {
                    for (uint32_t outputIndex = 0; outputIndex < tx.outputs.size(); ++outputIndex)
                    {
                        const auto &output = tx.outputs[outputIndex];
                        const uint64_t outputAmount = output.amount;

                        writer.StartObject();

                        writer.Key("index");
                        writer.Uint(outputIndex);

                        writer.Key("address");
                        /* Convert output key directly to address */
                        if (output.target.type() == typeid(Pastella::KeyOutput))
                        {
                            const auto &keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                            const std::string address = Utilities::publicKeyToAddress(keyOutput.key);
                            writer.String(address);
                        }
                        else
                        {
                            writer.String("[Unknown]");
                        }

                        writer.Key("amount");
                        writer.Uint64(outputAmount);

                        writer.Key("amount_formatted");
                        std::stringstream outputAmountStr;
                        outputAmountStr << std::fixed << std::setprecision(8) << (outputAmount / 100000000.0);
                        writer.String(outputAmountStr.str());

                        writer.EndObject();
                    }
                }
                writer.EndArray();

                /* TRANSPARENT SYSTEM: Input addresses (where funds are coming from) */
                writer.Key("inputs");
                writer.StartArray();
                {
                    for (const auto &input : tx.inputs)
                    {
                        if (input.type() == typeid(Pastella::KeyInput))
                        {
                            const auto &keyInput = boost::get<Pastella::KeyInput>(input);

                            writer.StartObject();

                            writer.Key("amount");
                            writer.Uint64(keyInput.amount);

                            writer.Key("amount_formatted");
                            std::stringstream inputAmountStr;
                            inputAmountStr << std::fixed << std::setprecision(8) << (keyInput.amount / 100000000.0);
                            writer.String(inputAmountStr.str());

                            /* TRANSPARENT SYSTEM: Output reference being spent */
                            writer.Key("spending");
                            writer.StartObject();

                            writer.Key("transaction_hash");
                            writer.String(Common::podToHex(keyInput.transactionHash));

                            writer.Key("output_index");
                            writer.Uint64(keyInput.outputIndex);

                            writer.EndObject();

                            /* Try to find the sender address from the previous transaction */
                            try
                            {
                                Pastella::Transaction prevTx;
                                const auto prevTxRaw = m_core->getTransaction(keyInput.transactionHash);

                                fromBinaryArray(prevTx, prevTxRaw.value());

                                /* Get the output from the previous transaction */
                                if (keyInput.outputIndex < prevTx.outputs.size())
                                {
                                    const auto &prevOutput = prevTx.outputs[keyInput.outputIndex];
                                    if (prevOutput.target.type() == typeid(Pastella::KeyOutput))
                                    {
                                        const auto &prevKeyOutput = boost::get<Pastella::KeyOutput>(prevOutput.target);
                                        /* Convert output key directly to address */
                                        const std::string address = Utilities::publicKeyToAddress(prevKeyOutput.key);
                                        writer.Key("from_address");
                                        writer.String(address);
                                    }
                                }
                            }
                            catch (...)
                            {
                                /* Failed to look up previous transaction - skip from_address */
                            }

                            writer.EndObject();
                        }
                    }
                }
                writer.EndArray();

                writer.EndObject();
            }
        }
        writer.EndArray();
    }
    writer.EndObject();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::queryBlocksLite(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    uint64_t timestamp = 0;

    if (hasMember(body, "timestamp"))
    {
        timestamp = getUint64FromJSON(body, "timestamp");
    }

    std::vector<Crypto::Hash> knownBlockHashes;

    if (hasMember(body, "blockIds"))
    {
        for (const auto &hashStrJson : getArrayFromJSON(body, "blockIds"))
        {
            Crypto::Hash hash;

            if (!Common::podFromHex(getStringFromJSONString(hashStrJson), hash))
            {
                failRequest(400, "Block hash specified is not a valid hex string!", res);
                return {SUCCESS, 400};
            }

            knownBlockHashes.push_back(hash);
        }
    }

    uint32_t startHeight;
    uint32_t currentHeight;
    uint32_t fullOffset;

    std::vector<Pastella::BlockShortInfo> blocks;

    if (!m_core->queryBlocksLite(knownBlockHashes, timestamp, startHeight, currentHeight, fullOffset, blocks))
    {
        failRequest(500, "Internal error: failed to queryblockslite", res);
        return {SUCCESS, 500};
    }

    writer.StartObject();

    writer.Key("fullOffset");
    writer.Uint64(fullOffset);

    writer.Key("currentHeight");
    writer.Uint64(currentHeight);

    writer.Key("startHeight");
    writer.Uint64(startHeight);

    writer.Key("items");
    writer.StartArray();
    {
        for (const auto block : blocks)
        {
            writer.StartObject();
            {
                writer.Key("blockShortInfo.block");
                writer.StartArray();
                {
                    for (const auto c : block.block)
                    {
                        writer.Uint64(c);
                    }
                }
                writer.EndArray();

                writer.Key("blockShortInfo.blockId");
                writer.String(Common::podToHex(block.blockId));

                writer.Key("blockShortInfo.txPrefixes");
                writer.StartArray();
                {
                    for (const auto prefix : block.txPrefixes)
                    {
                        writer.StartObject();
                        {
                            writer.Key("transactionPrefixInfo.txHash");
                            writer.String(Common::podToHex(prefix.txHash));

                            writer.Key("transactionPrefixInfo.txPrefix");
                            writer.StartObject();
                            {
                                writer.Key("extra");
                                writer.String(Common::toHex(prefix.txPrefix.extra));

                                writer.Key("unlock_time");
                                writer.Uint64(prefix.txPrefix.unlockTime);

                                writer.Key("version");
                                writer.Uint64(prefix.txPrefix.version);

                                writer.Key("vin");
                                writer.StartArray();
                                {
                                    for (const auto input : prefix.txPrefix.inputs)
                                    {
                                        const auto type = input.type() == typeid(Pastella::BaseInput)
                                            ? "ff"
                                            : "02";

                                        writer.StartObject();
                                        {
                                            writer.Key("type");
                                            writer.String(type);

                                            writer.Key("value");
                                            writer.StartObject();
                                            {
                                                if (input.type() == typeid(Pastella::BaseInput))
                                                {
                                                    writer.Key("height");
                                                    writer.Uint64(boost::get<Pastella::BaseInput>(input).blockIndex);

                                                    /* Add total generated amount for coinbase inputs */
                                                    uint64_t totalAmount = 0;
                                                    for (const auto &output : prefix.txPrefix.outputs)
                                                    {
                                                        totalAmount += output.amount;
                                                    }
                                                    writer.Key("amount");
                                                    writer.Uint64(totalAmount);
                                                }
                                                else
                                                {
                                                    const auto keyInput = boost::get<Pastella::KeyInput>(input);


                                                    writer.Key("amount");
                                                    writer.Uint64(keyInput.amount);

                                                    writer.Key("key_offsets");
                                                    writer.StartArray();
                                                    {
                                                        for (const auto index : keyInput.outputIndexes)
                                                        {
                                                            writer.Uint(index);
                                                        }
                                                    }
                                                    writer.EndArray();
                                                }
                                            }
                                            writer.EndObject();
                                        }
                                        writer.EndObject();
                                    }
                                }
                                writer.EndArray();

                                writer.Key("vout");
                                writer.StartArray();
                                {
                                    for (const auto output : prefix.txPrefix.outputs)
                                    {
                                        writer.StartObject();
                                        {
                                            writer.Key("amount");
                                            writer.Uint64(output.amount);

                                            writer.Key("target");
                                            writer.StartObject();
                                            {
                                                writer.Key("data");
                                                writer.StartObject();
                                                {
                                                    writer.Key("key");
                                                    writer.String(Common::podToHex(boost::get<Pastella::KeyOutput>(output.target).key));
                                                }
                                                writer.EndObject();

                                                writer.Key("type");
                                                writer.String("02");
                                            }
                                            writer.EndObject();
                                        }
                                        writer.EndObject();
                                    }
                                }
                                writer.EndArray();
                            }
                            writer.EndObject();
                        }
                        writer.EndObject();
                    }
                }
                writer.EndArray();
            }
            writer.EndObject();
        }
    }
    writer.EndArray();

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getTransactionsStatus(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    std::unordered_set<Crypto::Hash> transactionHashes;

    for (const auto &hashStr : getArrayFromJSON(body, "transactionHashes"))
    {
        Crypto::Hash hash;

        if (!Common::podFromHex(getStringFromJSONString(hashStr), hash))
        {
            failRequest(400, "Transaction hash specified is not a valid hex string!", res);
            return {SUCCESS, 400};
        }

        transactionHashes.insert(hash);
    }

    std::unordered_set<Crypto::Hash> transactionsInPool;
    std::unordered_set<Crypto::Hash> transactionsInBlock;
    std::unordered_set<Crypto::Hash> transactionsUnknown;

    const bool success = m_core->getTransactionsStatus(
        transactionHashes, transactionsInPool, transactionsInBlock, transactionsUnknown
    );

    if (!success)
    {
        failRequest(500, "Internal error: failed to getTransactionsStatus", res);
        return {SUCCESS, 500};
    }

    writer.StartObject();

    writer.Key("transactionsInBlock");
    writer.StartArray();
    {
        for (const auto &hash : transactionsInBlock)
        {
            writer.String(Common::podToHex(hash));
        }
    }
    writer.EndArray();

    writer.Key("transactionsInPool");
    writer.StartArray();
    {
        for (const auto &hash : transactionsInPool)
        {
            writer.String(Common::podToHex(hash));
        }
    }
    writer.EndArray();

    writer.Key("transactionsUnknown");
    writer.StartArray();
    {
        for (const auto &hash : transactionsUnknown)
        {
            writer.String(Common::podToHex(hash));
        }
    }
    writer.EndArray();

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getPoolChanges(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    Crypto::Hash lastBlockHash;

    if (!Common::podFromHex(getStringFromJSON(body, "tailBlockId"), lastBlockHash))
    {
        failRequest(400, "tailBlockId specified is not a valid hex string!", res);
        return {SUCCESS, 400};
    }

    std::vector<Crypto::Hash> knownHashes;

    for (const auto &hashStr : getArrayFromJSON(body, "knownTxsIds"))
    {
        Crypto::Hash hash;

        if (!Common::podFromHex(getStringFromJSONString(hashStr), hash))
        {
            failRequest(400, "Transaction hash specified is not a valid hex string!", res);
            return {SUCCESS, 400};
        }

        knownHashes.push_back(hash);
    }

    std::vector<Pastella::TransactionPrefixInfo> addedTransactions;
    std::vector<Crypto::Hash> deletedTransactions;

    const bool atTopOfChain = m_core->getPoolChangesLite(
        lastBlockHash, knownHashes, addedTransactions, deletedTransactions
    );

    writer.StartObject();

    writer.Key("addedTxs");
    writer.StartArray();
    {
        for (const auto prefix: addedTransactions)
        {
            writer.StartObject();
            {
                writer.Key("transactionPrefixInfo.txHash");
                writer.String(Common::podToHex(prefix.txHash));

                writer.Key("transactionPrefixInfo.txPrefix");
                writer.StartObject();
                {
                    writer.Key("extra");
                    writer.String(Common::toHex(prefix.txPrefix.extra));

                    writer.Key("unlock_time");
                    writer.Uint64(prefix.txPrefix.unlockTime);

                    writer.Key("version");
                    writer.Uint64(prefix.txPrefix.version);

                    writer.Key("vin");
                    writer.StartArray();
                    {
                        for (const auto input : prefix.txPrefix.inputs)
                        {
                            const auto type = input.type() == typeid(Pastella::BaseInput)
                                ? "ff"
                                : "02";

                            writer.StartObject();
                            {
                                writer.Key("type");
                                writer.String(type);

                                writer.Key("value");
                                writer.StartObject();
                                {
                                    if (input.type() == typeid(Pastella::BaseInput))
                                    {
                                        writer.Key("height");
                                        writer.Uint64(boost::get<Pastella::BaseInput>(input).blockIndex);

                                        /* Add total generated amount for coinbase inputs */
                                        uint64_t totalAmount = 0;
                                        for (const auto &output : prefix.txPrefix.outputs)
                                        {
                                            totalAmount += output.amount;
                                        }
                                        writer.Key("amount");
                                        writer.Uint64(totalAmount);
                                    }
                                    else
                                    {
                                        const auto keyInput = boost::get<Pastella::KeyInput>(input);


                                        writer.Key("amount");
                                        writer.Uint64(keyInput.amount);

                                        writer.Key("key_offsets");
                                        writer.StartArray();
                                        {
                                            for (const auto index : keyInput.outputIndexes)
                                            {
                                                writer.Uint(index);
                                            }
                                        }
                                        writer.EndArray();
                                    }
                                }
                                writer.EndObject();
                            }
                            writer.EndObject();
                        }
                    }
                    writer.EndArray();

                    writer.Key("vout");
                    writer.StartArray();
                    {
                        for (const auto output : prefix.txPrefix.outputs)
                        {
                            writer.StartObject();
                            {
                                writer.Key("amount");
                                writer.Uint64(output.amount);

                                writer.Key("target");
                                writer.StartObject();
                                {
                                    writer.Key("data");
                                    writer.StartObject();
                                    {
                                        writer.Key("key");
                                        writer.String(Common::podToHex(boost::get<Pastella::KeyOutput>(output.target).key));
                                    }
                                    writer.EndObject();

                                    writer.Key("type");
                                    writer.String("02");
                                }
                                writer.EndObject();
                            }
                            writer.EndObject();
                        }
                    }
                    writer.EndArray();
                }
                writer.EndObject();
            }
            writer.EndObject();
        }
    }
    writer.EndArray();

    writer.Key("deletedTxsIds");
    writer.StartArray();
    {
        for (const auto hash : deletedTransactions)
        {
            writer.String(Common::podToHex(hash));
        }
    }
    writer.EndArray();

    writer.Key("isTailBlockActual");
    writer.Bool(atTopOfChain);

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::queryBlocksDetailed(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    uint64_t timestamp = 0;

    if (hasMember(body, "timestamp"))
    {
        timestamp = getUint64FromJSON(body, "timestamp");
    }

    std::vector<Crypto::Hash> knownBlockHashes;

    if (hasMember(body, "blockIds"))
    {
        for (const auto &hashStrJson : getArrayFromJSON(body, "blockIds"))
        {
            Crypto::Hash hash;

            if (!Common::podFromHex(getStringFromJSONString(hashStrJson), hash))
            {
                failRequest(400, "Block hash specified is not a valid hex string!", res);
                return {SUCCESS, 400};
            }

            knownBlockHashes.push_back(hash);
        }
    }

    uint64_t startHeight;
    uint64_t currentHeight;
    uint64_t fullOffset;

    uint64_t blockCount = Pastella::BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;

    if (hasMember(body, "blockCount"))
    {
        blockCount = getUint64FromJSON(body, "blockCount");
    }

    std::vector<Pastella::BlockDetails> blocks;

    if (!m_core->queryBlocksDetailed(knownBlockHashes, timestamp, startHeight, currentHeight, fullOffset, blocks, blockCount))
    {
        failRequest(500, "Internal error: failed to queryblockslite", res);
        return {SUCCESS, 500};
    }

    writer.StartObject();

    writer.Key("fullOffset");
    writer.Uint64(fullOffset);

    writer.Key("currentHeight");
    writer.Uint64(currentHeight);

    writer.Key("startHeight");
    writer.Uint64(startHeight);

    writer.Key("blocks");
    writer.StartArray();
    {
        for (const auto block : blocks)
        {
            writer.StartObject();
            {
                writer.Key("major_version");
                writer.Uint64(block.majorVersion);

                writer.Key("minor_version");
                writer.Uint64(block.minorVersion);

                writer.Key("timestamp");
                writer.Uint64(block.timestamp);

                writer.Key("prevBlockHash");
                writer.String(Common::podToHex(block.prevBlockHash));

                writer.Key("index");
                writer.Uint64(block.index);

                writer.Key("hash");
                writer.String(Common::podToHex(block.hash));

                writer.Key("difficulty");
                writer.Uint64(block.difficulty);

                writer.Key("reward");
                writer.Uint64(block.reward);

                writer.Key("blockSize");
                writer.Uint64(block.blockSize);

                writer.Key("alreadyGeneratedCoins");
                auto stakingPool = m_core->getStakingPool();
                uint64_t totalPaidStakingRewards = stakingPool ? stakingPool->getTotalPaidStakingRewards() : 0;
                writer.String(std::to_string(m_core->getCurrency().calculateTotalGeneratedCoins(currentHeight, totalPaidStakingRewards)));

                writer.Key("alreadyGeneratedTransactions");
                writer.Uint64(block.alreadyGeneratedTransactions);

                writer.Key("sizeMedian");
                writer.Uint64(block.sizeMedian);

                writer.Key("baseReward");
                writer.Uint64(block.baseReward);

                writer.Key("nonce");
                writer.Uint64(block.nonce);

                writer.Key("totalFeeAmount");
                writer.Uint64(block.totalFeeAmount);

                writer.Key("transactionsCumulativeSize");
                writer.Uint64(block.transactionsCumulativeSize);

                writer.Key("transactions");
                writer.StartArray();
                {
                    for (const auto &tx : block.transactions)
                    {
                        writer.StartObject();
                        {
                            writer.Key("blockHash");
                            writer.String(Common::podToHex(block.hash));

                            writer.Key("blockIndex");
                            writer.Uint64(block.index);

                            writer.Key("extra");
                            writer.StartObject();
                            {
                                writer.Key("nonce");
                                writer.StartArray();
                                {
                                    for (const auto c : tx.extra.nonce)
                                    {
                                        writer.Uint64(c);
                                    }
                                }
                                writer.EndArray();

                                writer.Key("publicKey");
                                writer.String(Common::podToHex(tx.extra.publicKey));

                                writer.Key("raw");
                                writer.String(Common::toHex(tx.extra.raw));
                            }
                            writer.EndObject();

                            writer.Key("fee");
                            writer.Uint64(tx.fee);

                            writer.Key("hash");
                            writer.String(Common::podToHex(tx.hash));

                            writer.Key("inBlockchain");
                            writer.Bool(tx.inBlockchain);

                            writer.Key("inputs");
                            writer.StartArray();
                            {
                                for (const auto &input : tx.inputs)
                                {
                                    const auto type = input.type() == typeid(Pastella::BaseInputDetails)
                                        ? "ff"
                                        : "02";

                                    writer.StartObject();
                                    {
                                        writer.Key("type");
                                        writer.String(type);

                                        writer.Key("data");
                                        writer.StartObject();
                                        {
                                            if (input.type() == typeid(Pastella::BaseInputDetails))
                                            {
                                                const auto in = boost::get<Pastella::BaseInputDetails>(input);

                                                writer.Key("amount");
                                                writer.Uint64(in.amount);

                                                writer.Key("input");
                                                writer.StartObject();
                                                {
                                                    writer.Key("height");
                                                    writer.Uint64(in.input.blockIndex);
                                                }
                                                writer.EndObject();
                                            }
                                            else
                                            {
                                                const auto in = boost::get<Pastella::KeyInputDetails>(input);

                                                writer.Key("input");
                                                writer.StartObject();
                                                {
                                                    writer.Key("amount");
                                                    writer.Uint64(in.input.amount);


                                                    writer.Key("key_offsets");
                                                    writer.StartArray();
                                                    {
                                                        for (const auto index : in.input.outputIndexes)
                                                        {
                                                            writer.Uint(index);
                                                        }
                                                    }
                                                    writer.EndArray();

                                                }
                                                writer.EndObject();

                                                writer.Key("output");
                                                writer.StartObject();
                                                {
                                                    writer.Key("transactionHash");
                                                    writer.String(Common::podToHex(in.output.transactionHash));

                                                    writer.Key("number");
                                                    writer.Uint64(in.output.number);
                                                }
                                                writer.EndObject();
                                            }
                                        }
                                        writer.EndObject();
                                    }
                                    writer.EndObject();
                                }
                            }
                            writer.EndArray();

                            writer.Key("outputs");
                            writer.StartArray();
                            {
                                for (const auto &output : tx.outputs)
                                {
                                    writer.StartObject();
                                    {
                                        writer.Key("globalIndex");
                                        writer.Uint64(output.globalIndex);

                                        writer.Key("output");
                                        writer.StartObject();
                                        {
                                            writer.Key("amount");
                                            writer.Uint64(output.output.amount);

                                            writer.Key("target");
                                            writer.StartObject();
                                            {
                                                writer.Key("data");
                                                writer.StartObject();
                                                {
                                                    writer.Key("key");
                                                    writer.String(Common::podToHex(boost::get<Pastella::KeyOutput>(output.output.target).key));
                                                }
                                                writer.EndObject();

                                                writer.Key("type");
                                                writer.String("02");
                                            }
                                            writer.EndObject();
                                        }
                                        writer.EndObject();
                                    }
                                    writer.EndObject();
                                }
                            }
                            writer.EndArray();

                            

                            writer.Key("signatures");
                            writer.StartArray();
                            {
                                int i = 0;

                                for (const auto &sigs : tx.signatures)
                                {
                                    for (const auto &sig : sigs)
                                    {
                                        writer.StartObject();
                                        {
                                            writer.Key("first");
                                            writer.Uint64(i);

                                            writer.Key("second");
                                            writer.String(Common::podToHex(sig));
                                        }
                                        writer.EndObject();
                                    }

                                    i++;
                                }
                            }
                            writer.EndArray();

                            writer.Key("signaturesSize");
                            writer.Uint64(tx.signatures.size());

                            writer.Key("size");
                            writer.Uint64(tx.size);

                            writer.Key("timestamp");
                            writer.Uint64(tx.timestamp);

                            writer.Key("totalInputsAmount");
                            writer.Uint64(tx.totalInputsAmount);

                            writer.Key("totalOutputsAmount");
                            writer.Uint64(tx.totalOutputsAmount);

                            writer.Key("unlockTime");
                            writer.Uint64(tx.unlockTime);
                        }
                        writer.EndObject();
                    }
                }
                writer.EndArray();
            }
            writer.EndObject();
        }
    }
    writer.EndArray();

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getRawBlocks(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    std::vector<Crypto::Hash> blockHashCheckpoints;

    if (hasMember(body, "blockHashCheckpoints"))
    {
        for (const auto &jsonHash : getArrayFromJSON(body, "blockHashCheckpoints"))
        {
            std::string hashStr = jsonHash.GetString();

            Crypto::Hash hash;
            Common::podFromHex(hashStr, hash);

            blockHashCheckpoints.push_back(hash);
        }
    }

    const uint64_t startHeight = hasMember(body, "startHeight")
        ? getUint64FromJSON(body, "startHeight")
        : 0;

    const uint64_t startTimestamp = hasMember(body, "startTimestamp")
        ? getUint64FromJSON(body, "startTimestamp")
        : 0;

    const uint64_t blockCount = hasMember(body, "blockCount")
        ? getUint64FromJSON(body, "blockCount")
        : 100;

    const bool skipCoinbaseTransactions = hasMember(body, "skipCoinbaseTransactions")
        ? getBoolFromJSON(body, "skipCoinbaseTransactions")
        : false;

    std::vector<Pastella::RawBlock> blocks;
    std::optional<WalletTypes::TopBlock> topBlockInfo;

    const bool success = m_core->getRawBlocks(
        blockHashCheckpoints,
        startHeight,
        startTimestamp,
        blockCount,
        skipCoinbaseTransactions,
        blocks,
        topBlockInfo
    );

    if (!success)
    {
        return {SUCCESS, 500};
    }

    writer.Key("items");
    writer.StartArray();
    {
        for (const auto &block : blocks)
        {
            writer.StartObject();

            writer.Key("block");
            writer.String(Common::toHex(block.block));

            writer.Key("transactions");
            writer.StartArray();
            for (const auto &transaction : block.transactions)
            {
                writer.String(Common::toHex(transaction));
            }
            writer.EndArray();

            writer.EndObject();
        }
    }
    writer.EndArray();

    if (topBlockInfo)
    {
        writer.Key("topBlock");
        writer.StartObject();
        {
            writer.Key("hash");
            writer.String(Common::podToHex(topBlockInfo->hash));

            writer.Key("height");
            writer.Uint64(topBlockInfo->height);
        }
        writer.EndObject();
    }

    writer.Key("synced");
    writer.Bool(blocks.empty());

    writer.Key("status");
    writer.String("OK");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

///////////////////////
/* STAKING RPC METHODS */
///////////////////////

std::tuple<Error, uint16_t> RpcServer::getStakingPoolInfo(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    auto stakingPool = m_core->getStakingPool();
    if (!stakingPool)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Staking pool not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    uint64_t currentHeight = m_core->getTopBlockIndex() + 1;
    bool stakingEnabled = currentHeight >= Pastella::parameters::staking::STAKING_ENABLE_HEIGHT;

    writer.Key("status");
    writer.String("OK");

    writer.Key("staking_enabled");
    writer.Bool(stakingEnabled);

    writer.Key("staking_enable_height");
    writer.Uint64(Pastella::parameters::staking::STAKING_ENABLE_HEIGHT);

    writer.Key("current_height");
    writer.Uint64(currentHeight);

    writer.Key("minimum_stake");
    writer.Uint64(Pastella::parameters::staking::MIN_STAKING_AMOUNT);

    writer.Key("total_staked");
    writer.Uint64(stakingPool->getTotalStakedAmount());

    writer.Key("pending_stakes");
    writer.Uint64(0); // TODO: Add pending staking amount calculation

    writer.Key("total_pool_balance");
    writer.Uint64(stakingPool->getTotalPoolBalance());

    writer.Key("available_balance");
    writer.Uint64(stakingPool->getAvailableBalance());

    writer.Key("current_height");
    writer.Uint64(m_core->getTopBlockIndex() + 1);

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getPendingRewards(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    const auto *addressVal = getParamValue("address");
    if (!addressVal || !addressVal->IsString())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: address");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    std::string address = std::string(addressVal->GetString());
    auto stakingPool = m_core->getStakingPool();
    if (!stakingPool)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Staking pool not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    auto pendingRewards = stakingPool->getPendingRewards(address);

    writer.Key("status");
    writer.String("OK");

    writer.Key("address");
    writer.String(address);

    writer.Key("pending_rewards");
    writer.Uint64(pendingRewards);

    writer.Key("current_height");
    writer.Uint64(m_core->getTopBlockIndex() + 1);

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getUserStakes(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    // Require staking_hashes parameter
    const auto *hashesVal = getParamValue("staking_hashes");
    if (!hashesVal)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing required parameter: staking_hashes");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    if (!hashesVal->IsArray())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("staking_hashes must be an array");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    if (hashesVal->Size() == 0)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("staking_hashes must contain at least one hash");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    std::vector<std::string> stakingHashes;
    for (rapidjson::SizeType i = 0; i < hashesVal->Size(); i++)
    {
        const rapidjson::Value &hash = (*hashesVal)[i];
        if (!hash.IsString())
        {
            writer.Key("status");
            writer.String("ERROR");
            writer.Key("message");
            writer.String("All staking hashes must be strings");
            res.body = sb.GetString();
            return {SUCCESS, 400};
        }
        stakingHashes.push_back(std::string(hash.GetString()));
    }

    auto stakingPool = m_core->getStakingPool();
    if (!stakingPool)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Staking pool not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    std::vector<Pastella::StakingEntry> userStakes = stakingPool->getStakesByHashes(stakingHashes);

    /* Get current block height for reward calculations */
    uint64_t currentHeight = m_core->getTopBlockIndex() + 1;

    writer.Key("status");
    writer.String("OK");

    writer.Key("stake_count");
    writer.Uint64(userStakes.size());

    writer.Key("stakes");
    writer.StartArray();
    for (auto &stake : userStakes)
    {
        /* Calculate enhanced reward data */
        stakingPool->calculateDetailedRewards(stake, currentHeight);

        writer.StartObject();

        writer.Key("amount");
        writer.Uint64(stake.amount);

        writer.Key("unlock_time");
        writer.Uint64(stake.unlockTime);

        writer.Key("lock_duration_days");
        writer.Uint64(stake.lockDurationDays);

        writer.Key("staking_tx_hash");
        writer.String(stake.stakingTxHash);

        writer.Key("accumulated_reward");
        writer.Uint64(stake.accumulatedReward);

        writer.Key("creation_height");
        writer.Uint64(stake.creationHeight);

        writer.Key("is_active");
        writer.Bool(stake.isActive);

        /* Enhanced reward calculation fields */
        writer.Key("blocks_staked");
        writer.Uint64(stake.blocksStaked);

        writer.Key("est_daily_reward");
        writer.Uint64(stake.estDailyReward);

        writer.Key("est_weekly_reward");
        writer.Uint64(stake.estWeeklyReward);

        writer.Key("est_monthly_reward");
        writer.Uint64(stake.estMonthlyReward);

        writer.Key("est_yearly_reward");
        writer.Uint64(stake.estYearlyReward);

        writer.Key("total_reward_at_maturity");
        writer.Uint64(stake.totalRewardAtMaturity);

        writer.Key("total_payout_at_maturity");
        writer.Uint64(stake.amount + stake.totalRewardAtMaturity);

        writer.Key("accumulated_earnings");
        writer.Uint64(stake.accumulatedEarnings);

        /* TRANSPARENT SYSTEM: rewardAddress removed - use stakerAddress instead */
        std::string stakerAddress = stake.stakerAddress;

        writer.Key("staker_address");
        writer.String(stakerAddress);

        writer.EndObject();
    }
    writer.EndArray();

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}



std::tuple<Error, uint16_t> RpcServer::getAllStakes(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    /* Parse pagination parameters with defaults */
    uint64_t page = 1;
    uint64_t limit = 100;

    const auto *pageVal = getParamValue("page");
    if (pageVal && pageVal->IsUint64())
    {
        page = pageVal->GetUint64();
    }

    const auto *limitVal = getParamValue("limit");
    if (limitVal && limitVal->IsUint64())
    {
        limit = limitVal->GetUint64();
    }

    /* Validate pagination parameters */
    if (page == 0)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Invalid parameter: page must be greater than 0");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    if (limit == 0 || limit > 1000)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Invalid parameter: limit must be between 1 and 1000");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    auto stakingPool = m_core->getStakingPool();
    if (!stakingPool)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Staking pool not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    /* Get all active stakes */
    std::vector<Pastella::StakingEntry> allStakes = stakingPool->getActiveStakes();
    std::vector<Pastella::StakingEntry> finishedStakes = stakingPool->getInactiveStakes();
    uint64_t totalStakes = allStakes.size();
    uint64_t totalPages = (totalStakes == 0) ? 1 : (totalStakes + limit - 1) / limit; /* Ceiling division */

    /* Validate page number */
    if (page > totalPages)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Invalid parameter: page exceeds total pages");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    /* Calculate pagination indices */
    uint64_t startIndex = (page - 1) * limit;
    uint64_t endIndex = std::min(startIndex + limit, totalStakes);

    /* Get current block height for reward calculations */
    uint64_t currentHeight = m_core->getTopBlockIndex() + 1;

    /* Calculate total staked and total earned across all stakes */
    uint64_t totalAmountStaked = 0;
    uint64_t totalEarned = 0;
    for (const auto &stake : allStakes)
    {
        totalAmountStaked += stake.amount;
        totalEarned += stake.accumulatedReward;
    }

    writer.Key("status");
    writer.String("OK");

    writer.Key("pagination");
    writer.StartObject();
    writer.Key("total_stakes");
    writer.Uint64(totalStakes);
    writer.Key("current_page");
    writer.Uint64(page);
    writer.Key("total_pages");
    writer.Uint64(totalPages);
    writer.Key("limit");
    writer.Uint64(limit);
    writer.Key("start_index");
    writer.Uint64(startIndex);
    writer.Key("end_index");
    writer.Uint64(endIndex);
    writer.EndObject();

    writer.Key("current_height");
    writer.Uint64(currentHeight);

    writer.Key("total_staked");
    writer.Uint64(totalAmountStaked);

    writer.Key("total_staked_formatted");
    std::stringstream totalStakedStr;
    totalStakedStr << std::fixed << std::setprecision(8) << (totalAmountStaked / 100000000.0);
    writer.String(totalStakedStr.str());

    writer.Key("total_earned");
    writer.Uint64(totalEarned);

    writer.Key("total_earned_formatted");
    std::stringstream totalEarnedStr;
    totalEarnedStr << std::fixed << std::setprecision(8) << (totalEarned / 100000000.0);
    writer.String(totalEarnedStr.str());

    writer.Key("stakes");
    writer.StartArray();

    /* Output paginated stakes with enhanced information */
    for (uint64_t i = startIndex; i < endIndex; i++)
    {
        Pastella::StakingEntry &stake = allStakes[i];

        /* Calculate enhanced reward data */
        stakingPool->calculateDetailedRewards(stake, currentHeight);

        writer.StartObject();

        /* Basic stake information */
        writer.Key("staking_tx_hash");
        writer.String(stake.stakingTxHash);

        writer.Key("staker_address");
        writer.String(stake.stakerAddress);

        writer.Key("amount");
        writer.Uint64(stake.amount);

        writer.Key("lock_duration_days");
        writer.Uint64(stake.lockDurationDays);

        writer.Key("unlock_time");
        writer.Uint64(stake.unlockTime);

        writer.Key("creation_height");
        writer.Uint64(stake.creationHeight);

        writer.Key("is_active");
        writer.Bool(stake.isActive);

        /* Time calculations */
        uint64_t blocksStaked = currentHeight - stake.creationHeight;
        uint64_t blocksRemaining = 0;

        if (currentHeight < stake.unlockTime)
        {
            blocksRemaining = stake.unlockTime - currentHeight;
        }

        writer.Key("blocks_staked");
        writer.Uint64(blocksStaked);

        writer.Key("blocks_remaining");
        writer.Uint64(blocksRemaining);

        writer.Key("progress_percentage");
        writer.Double((stake.lockDurationDays > 0) ? (double(blocksStaked) / double(stake.lockDurationDays * 2880) * 100.0) : 0.0); /* Assuming 30s blocks = 2880 blocks/day */

        /* Reward information */
        writer.Key("accumulated_reward");
        writer.Uint64(stake.accumulatedReward);

        writer.Key("accumulated_earnings");
        writer.Uint64(stake.accumulatedEarnings);

        writer.Key("daily_reward_rate");
        writer.Uint64(stake.dailyRewardRate);

        /* Estimated rewards */
        writer.Key("est_daily_reward");
        writer.Uint64(stake.estDailyReward);

        writer.Key("est_weekly_reward");
        writer.Uint64(stake.estWeeklyReward);

        writer.Key("est_monthly_reward");
        writer.Uint64(stake.estMonthlyReward);

        writer.Key("est_yearly_reward");
        writer.Uint64(stake.estYearlyReward);

        writer.Key("total_reward_at_maturity");
        writer.Uint64(stake.totalRewardAtMaturity);

        /* Total payout at maturity */
        writer.Key("total_payout_at_maturity");
        writer.Uint64(stake.amount + stake.totalRewardAtMaturity);

        /* ROI calculations */
        writer.Key("roi_daily");
        writer.Double((stake.amount > 0) ? (double(stake.estDailyReward) / double(stake.amount) * 100.0) : 0.0);

        writer.Key("roi_yearly");
        writer.Double((stake.amount > 0) ? (double(stake.estYearlyReward) / double(stake.amount) * 100.0) : 0.0);

        /* Status information */
        writer.Key("status");
        if (!stake.isActive)
        {
            writer.String("completed");
        }
        else if (currentHeight >= stake.unlockTime)
        {
            writer.String("mature");
        }
        else
        {
            writer.String("active");
        }

        writer.EndObject();
    }

    writer.EndArray();

    /* Add finished (inactive) stakes */
    writer.Key("finished_stakes");
    writer.StartArray();

    /* Output all finished stakes with their information */
    for (const auto &stake : finishedStakes)
    {
        /* Create a mutable copy for reward calculation */
        Pastella::StakingEntry stakeCopy = stake;
        stakingPool->calculateDetailedRewards(stakeCopy, currentHeight);

        writer.StartObject();

        /* Basic stake information */
        writer.Key("staking_tx_hash");
        writer.String(stakeCopy.stakingTxHash);

        writer.Key("staker_address");
        writer.String(stakeCopy.stakerAddress);

        writer.Key("amount");
        writer.Uint64(stakeCopy.amount);

        writer.Key("lock_duration_days");
        writer.Uint64(stakeCopy.lockDurationDays);

        writer.Key("unlock_time");
        writer.Uint64(stakeCopy.unlockTime);

        writer.Key("creation_height");
        writer.Uint64(stakeCopy.creationHeight);

        writer.Key("is_active");
        writer.Bool(stakeCopy.isActive);

        /* Time calculations */
        uint64_t blocksStaked = stakeCopy.unlockTime - stakeCopy.creationHeight; /* Total blocks staked */
        uint64_t blocksRemaining = 0; /* Finished, so no remaining blocks */

        writer.Key("blocks_staked");
        writer.Uint64(blocksStaked);

        writer.Key("blocks_remaining");
        writer.Uint64(blocksRemaining);

        writer.Key("progress_percentage");
        writer.Double(100.0); /* Completed: 100% */

        /* Reward information */
        writer.Key("accumulated_reward");
        writer.Uint64(stakeCopy.accumulatedReward);

        writer.Key("accumulated_earnings");
        writer.Uint64(stakeCopy.accumulatedEarnings);

        writer.Key("daily_reward_rate");
        writer.Uint64(stakeCopy.dailyRewardRate);

        /* Estimated rewards (for historical reference) */
        writer.Key("est_daily_reward");
        writer.Uint64(stakeCopy.estDailyReward);

        writer.Key("est_weekly_reward");
        writer.Uint64(stakeCopy.estWeeklyReward);

        writer.Key("est_monthly_reward");
        writer.Uint64(stakeCopy.estMonthlyReward);

        writer.Key("est_yearly_reward");
        writer.Uint64(stakeCopy.estYearlyReward);

        writer.Key("total_reward_at_maturity");
        writer.Uint64(stakeCopy.totalRewardAtMaturity);

        /* Total payout at maturity (expected) */
        writer.Key("total_payout_at_maturity");
        writer.Uint64(stakeCopy.amount + stakeCopy.totalRewardAtMaturity);

        /* ROI calculations (for historical reference) */
        writer.Key("roi_daily");
        writer.Double((stakeCopy.amount > 0) ? (double(stakeCopy.estDailyReward) / double(stakeCopy.amount) * 100.0) : 0.0);

        writer.Key("roi_yearly");
        writer.Double((stakeCopy.amount > 0) ? (double(stakeCopy.estYearlyReward) / double(stakeCopy.amount) * 100.0) : 0.0);

        /* Actual rewards earned */
        writer.Key("earned_rewards");
        writer.Uint64(stakeCopy.accumulatedReward);

        writer.Key("earned_rewards_formatted");
        std::stringstream earnedRewardsStr;
        earnedRewardsStr << std::fixed << std::setprecision(8) << (stakeCopy.accumulatedReward / 100000000.0);
        writer.String(earnedRewardsStr.str());

        /* Total payout received (actual) */
        writer.Key("total_payout");
        writer.Uint64(stakeCopy.amount + stakeCopy.accumulatedReward);

        writer.Key("total_payout_formatted");
        std::stringstream totalPayoutStr;
        totalPayoutStr << std::fixed << std::setprecision(8) << ((stakeCopy.amount + stakeCopy.accumulatedReward) / 100000000.0);
        writer.String(totalPayoutStr.str());

        /* Status information */
        writer.Key("status");
        writer.String("completed");

        writer.EndObject();
    }

    writer.EndArray();
    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

/* UTXO SYSTEM: Get a specific UTXO by transaction hash and output index
 *
 * RPC Method: getutxo
 *
 * Parameters:
 *   - hash: Transaction hash (hex string)
 *   - index: Output index (uint32_t)
 *
 * Returns:
 *   - status: "OK" or "ERROR"
 *   - utxo: UTXO data (if found)
 *     - amount: Output amount
 *     - public_key: Output public key
 *     - block_index: Block containing the UTXO
 *     - transaction_hash: Transaction creating the UTXO
 *     - output_index: Output index in transaction
 *     - spent: Whether UTXO is spent
 *     - spent_block_index: Block where UTXO was spent (0 if unspent)
 *
 * Example:
 * {
 *   "jsonrpc": "2.0",
 *   "method": "getutxo",
 *   "params": {
 *     "hash": "abcd1234...",
 *     "index": 0
 *   }
 * } */
std::tuple<Error, uint16_t> RpcServer::getUtxo(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    /* Get parameters */
    std::string hashStr;
    uint32_t outputIndex = 0;

    /* Get params object */
    const auto params = getObjectFromJSON(body, "params");

    /* Get transaction hash (required) */
    if (params.HasMember("hash") && params["hash"].IsString())
    {
        hashStr = params["hash"].GetString();
    }
    else
    {
        writer.StartObject();

        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String("Transaction hash parameter is required");

        writer.EndObject();

        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    /* Get output index (required) */
    if (params.HasMember("index") && params["index"].IsUint())
    {
        outputIndex = params["index"].GetUint();
    }
    else
    {
        writer.StartObject();

        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String("Output index parameter is required");

        writer.EndObject();

        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    /* Convert hex hash to Crypto::Hash */
    Crypto::Hash transactionHash;
    if (!Common::podFromHex(hashStr, transactionHash))
    {
        writer.StartObject();

        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String("Invalid transaction hash format");

        writer.EndObject();

        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    writer.StartObject();

    try
    {
        /* Get UTXO from core */
        Pastella::UtxoOutput utxo;
        bool found = m_core->getUtxo(transactionHash, outputIndex, utxo);

        if (found)
        {
            writer.Key("status");
            writer.String("OK");

            writer.Key("utxo");
            writer.StartObject();

            writer.Key("amount");
            writer.Uint64(utxo.amount);

            writer.Key("public_key");
            writer.String(Common::podToHex(utxo.publicKey));

            writer.Key("block_index");
            writer.Uint(utxo.blockIndex);

            writer.Key("transaction_hash");
            writer.String(Common::podToHex(utxo.transactionHash));

            writer.Key("output_index");
            writer.Uint(utxo.outputIndex);

            writer.Key("spent");
            writer.Bool(utxo.spent);

            writer.Key("spent_block_index");
            writer.Uint(utxo.spentBlockIndex);

            writer.EndObject();
        }
        else
        {
            writer.Key("status");
            writer.String("ERROR");

            writer.Key("message");
            writer.String("UTXO not found");
        }
    }
    catch (const std::exception &e)
    {
        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String(std::string("Failed to get UTXO: ") + e.what());
    }

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

/* UTXO SYSTEM: Get all UTXOs for a transaction
 *
 * RPC Method: getutxosfortx
 *
 * Parameters:
 *   - hash: Transaction hash (hex string)
 *
 * Returns:
 *   - status: "OK" or "ERROR"
 *   - utxos: Array of UTXO data (if found)
 *     - amount: Output amount
 *     - public_key: Output public key
 *     - block_index: Block containing the UTXO
 *     - transaction_hash: Transaction creating the UTXO
 *     - output_index: Output index in transaction
 *     - spent: Whether UTXO is spent
 *     - spent_block_index: Block where UTXO was spent (0 if unspent)
 *
 * Example:
 * {
 *   "jsonrpc": "2.0",
 *   "method": "getutxosfortx",
 *   "params": {
 *     "hash": "abcd1234..."
 *   }
 * } */
std::tuple<Error, uint16_t> RpcServer::getUtxosForTransaction(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    /* Get parameters */
    std::string hashStr;

    /* Get params object */
    const auto params = getObjectFromJSON(body, "params");

    /* Get transaction hash (required) */
    if (params.HasMember("hash") && params["hash"].IsString())
    {
        hashStr = params["hash"].GetString();
    }
    else
    {
        writer.StartObject();

        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String("Transaction hash parameter is required");

        writer.EndObject();

        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    /* Convert hex hash to Crypto::Hash */
    Crypto::Hash transactionHash;
    if (!Common::podFromHex(hashStr, transactionHash))
    {
        writer.StartObject();

        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String("Invalid transaction hash format");

        writer.EndObject();

        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    writer.StartObject();

    try
    {
        /* Get UTXOs from core */
        std::vector<Pastella::UtxoOutput> utxos = m_core->getUtxosForTransaction(transactionHash);

        writer.Key("status");
        writer.String("OK");

        writer.Key("utxo_count");
        writer.Uint64(utxos.size());

        writer.Key("utxos");
        writer.StartArray();

        for (const auto &utxo : utxos)
        {
            writer.StartObject();

            writer.Key("amount");
            writer.Uint64(utxo.amount);

            writer.Key("public_key");
            writer.String(Common::podToHex(utxo.publicKey));

            writer.Key("block_index");
            writer.Uint(utxo.blockIndex);

            writer.Key("transaction_hash");
            writer.String(Common::podToHex(utxo.transactionHash));

            writer.Key("output_index");
            writer.Uint(utxo.outputIndex);

            writer.Key("spent");
            writer.Bool(utxo.spent);

            writer.Key("spent_block_index");
            writer.Uint(utxo.spentBlockIndex);

            writer.EndObject();
        }

        writer.EndArray();
    }
    catch (const std::exception &e)
    {
        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String(std::string("Failed to get UTXOs: ") + e.what());
    }

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

/* Governance RPC Method Implementations */

std::tuple<Error, uint16_t> RpcServer::getGovernanceProposals(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if governance is enabled */
    uint64_t currentHeight = m_core->getTopBlockIndex() + 1;
    bool governanceEnabled = currentHeight >= Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT;

    if (!governanceEnabled)
    {
        writer.Key("status");
        writer.String("ERROR");

        writer.Key("message");
        writer.String("Governance system is not enabled yet");

        writer.Key("governance_enable_height");
        writer.Uint64(Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT);

        writer.Key("current_height");
        writer.Uint64(currentHeight);

        writer.EndObject();

        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    auto governanceManager = m_core->getGovernanceManager();
    if (!governanceManager)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Governance manager not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    /* Check if active_only filter is set */
    bool activeOnly = false;
    const auto *activeOnlyVal = getParamValue("active_only");
    if (activeOnlyVal && activeOnlyVal->IsBool())
    {
        activeOnly = activeOnlyVal->GetBool();
    }

    /* Get proposals */
    std::vector<WalletTypes::GovernanceProposal> proposals;
    if (activeOnly)
    {
        proposals = governanceManager->getActiveProposals();
    }
    else
    {
        proposals = governanceManager->getAllProposals();
    }

    writer.Key("status");
    writer.String("OK");

    writer.Key("governance_enabled");
    writer.Bool(governanceEnabled);

    writer.Key("current_height");
    writer.Uint64(currentHeight);

    writer.Key("proposal_count");
    writer.Uint64(proposals.size());

    writer.Key("proposals");
    writer.StartArray();

    for (const auto &proposal : proposals)
    {
        proposal.toJSON(writer);
    }

    writer.EndArray();
    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getProposalDetails(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    /* Get proposal_id parameter */
    const auto *proposalIdVal = getParamValue("proposal_id");
    if (!proposalIdVal || !proposalIdVal->IsUint64())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: proposal_id");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    uint64_t proposalId = proposalIdVal->GetUint64();

    auto governanceManager = m_core->getGovernanceManager();
    if (!governanceManager)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Governance manager not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    /* Get proposal */
    WalletTypes::GovernanceProposal proposal;
    if (!governanceManager->getProposal(proposalId, proposal))
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Proposal not found");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    writer.Key("status");
    writer.String("OK");

    writer.Key("proposal");
    proposal.toJSON(writer);

    /* Get votes for this proposal */
    std::vector<WalletTypes::GovernanceVote> votes = governanceManager->getVotes(proposalId);

    writer.Key("votes");
    writer.StartArray();

    for (const auto &vote : votes)
    {
        vote.toJSON(writer);
    }

    writer.EndArray();
    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::createProposal(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    /* Get title parameter */
    const auto *titleVal = getParamValue("title");
    if (!titleVal || !titleVal->IsString())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: title");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    std::string title = titleVal->GetString();

    /* Get description parameter */
    const auto *descVal = getParamValue("description");
    if (!descVal || !descVal->IsString())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: description");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    std::string description = descVal->GetString();

    /* Get proposal_type parameter */
    const auto *typeVal = getParamValue("proposal_type");
    if (!typeVal || !typeVal->IsUint())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: proposal_type");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    uint8_t proposalType = typeVal->GetUint();

    auto governanceManager = m_core->getGovernanceManager();
    if (!governanceManager)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Governance manager not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    /* Validate proposal type */
    if (proposalType > Pastella::parameters::governance::PROPOSAL_TYPE_TREASURY)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Invalid proposal type");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    /* For treasury proposals (type 2), validate amount and recipient */
    uint64_t amount = 0;
    std::string recipientAddress = "";

    if (proposalType == Pastella::parameters::governance::PROPOSAL_TYPE_TREASURY)
    {
        /* Get amount parameter */
        const auto *amountVal = getParamValue("amount");
        if (!amountVal || !amountVal->IsUint64())
        {
            writer.Key("status");
            writer.String("ERROR");
            writer.Key("message");
            writer.String("Missing parameter: amount (required for treasury proposals)");
            res.body = sb.GetString();
            return {SUCCESS, 400};
        }

        amount = amountVal->GetUint64();

        /* Validate amount is greater than 0 */
        if (amount == 0)
        {
            writer.Key("status");
            writer.String("ERROR");
            writer.Key("message");
            writer.String("Amount must be greater than 0");
            res.body = sb.GetString();
            return {SUCCESS, 400};
        }

        /* Get recipient_address parameter */
        const auto *recipientVal = getParamValue("recipient_address");
        if (!recipientVal || !recipientVal->IsString())
        {
            writer.Key("status");
            writer.String("ERROR");
            writer.Key("message");
            writer.String("Missing parameter: recipient_address (required for treasury proposals)");
            res.body = sb.GetString();
            return {SUCCESS, 400};
        }

        recipientAddress = recipientVal->GetString();

        /* Validate recipient address is not empty */
        if (recipientAddress.empty())
        {
            writer.Key("status");
            writer.String("ERROR");
            writer.Key("message");
            writer.String("Recipient address cannot be empty");
            res.body = sb.GetString();
            return {SUCCESS, 400};
        }
    }

    /* Create proposal (proposer address will be extracted from transaction when mined) */
    uint64_t currentHeight = m_core->getTopBlockIndex() + 1;
    uint64_t proposalId = governanceManager->createProposal(
        title,
        description,
        "", /* Proposer address - will be set from transaction */
        proposalType,
        currentHeight,
        amount,
        recipientAddress
    );

    writer.Key("status");
    writer.String("OK");

    writer.Key("proposal_id");
    writer.Uint64(proposalId);

    writer.Key("message");
    writer.String("Proposal created successfully");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getNextProposalId(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Get governance manager */
    const auto governanceManager = m_core->getGovernanceManager();

    /* Check if governance manager is available */
    if (!governanceManager)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Governance manager not available");
        res.body = sb.GetString();
        return {SUCCESS, 404};
    }

    /* Get next proposal ID */
    uint64_t nextProposalId = governanceManager->getNextProposalId();

    writer.Key("status");
    writer.String("OK");

    writer.Key("next_proposal_id");
    writer.Uint64(nextProposalId);

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::castVote(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    /* Get proposal_id parameter */
    const auto *proposalIdVal = getParamValue("proposal_id");
    if (!proposalIdVal || !proposalIdVal->IsUint64())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: proposal_id");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    uint64_t proposalId = proposalIdVal->GetUint64();

    /* Get vote parameter */
    const auto *voteVal = getParamValue("vote");
    if (!voteVal || !voteVal->IsUint())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: vote");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    uint8_t vote = voteVal->GetUint();

    auto governanceManager = m_core->getGovernanceManager();
    if (!governanceManager)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Governance manager not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    /* Get address parameter (optional for response) */
    std::string address = "";
    const auto *addressVal = getParamValue("address");
    if (addressVal && addressVal->IsString())
    {
        address = addressVal->GetString();
    }

    /* Calculate voting power from staking pool */
    uint64_t votingPower = 0;
    if (!address.empty())
    {
        auto stakingPool = m_core->getStakingPool();
        if (stakingPool)
        {
            uint64_t currentHeight = m_core->getTopBlockIndex() + 1;
            votingPower = stakingPool->getVotingPower(address, currentHeight);
        }
    }

    /* Cast vote (voter address and stake weight will be extracted from transaction when mined) */
    uint64_t currentHeight = m_core->getTopBlockIndex() + 1;
    bool success = governanceManager->castVote(
        proposalId,
        address.empty() ? "unknown" : address, /* Will be updated from transaction */
        vote,
        votingPower,
        currentHeight
    );

    if (!success)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Failed to cast vote (proposal not found, not active, or already voted)");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    writer.Key("status");
    writer.String("OK");

    writer.Key("voting_power");
    writer.Uint64(votingPower);

    writer.Key("message");
    writer.String("Vote cast successfully");

    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}

std::tuple<Error, uint16_t> RpcServer::getVotingPower(
    const httplib::Request &req,
    httplib::Response &res,
    const rapidjson::Document &body)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    /* Check if called through json_rpc (has params) or directly */
    const rapidjson::Value *params = nullptr;
    if (hasMember(body, "params") && body["params"].IsObject())
    {
        params = &body["params"];
    }

    /* Helper lambda to get a parameter value from either params or body */
    auto getParamValue = [&params, &body](const char *key) -> const rapidjson::Value* {
        if (params && params->HasMember(key))
        {
            return &(*params)[key];
        }
        if (body.HasMember(key))
        {
            return &body[key];
        }
        return nullptr;
    };

    /* Get address parameter */
    const auto *addressVal = getParamValue("address");
    if (!addressVal || !addressVal->IsString())
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Missing parameter: address");
        res.body = sb.GetString();
        return {SUCCESS, 400};
    }

    std::string address = addressVal->GetString();

    auto stakingPool = m_core->getStakingPool();
    if (!stakingPool)
    {
        writer.Key("status");
        writer.String("ERROR");
        writer.Key("message");
        writer.String("Staking pool not available");
        res.body = sb.GetString();
        return {SUCCESS, 200};
    }

    /* Get voting power */
    uint64_t currentHeight = m_core->getTopBlockIndex() + 1;
    uint64_t votingPower = stakingPool->getVotingPower(address, currentHeight);

    /* Get active stakes for detailed breakdown */
    std::vector<Pastella::StakingEntry> allStakes = stakingPool->getActiveStakes();
    std::vector<Pastella::StakingEntry> userStakes;

    for (const auto &stake : allStakes)
    {
        if (stake.stakerAddress == address)
        {
            userStakes.push_back(stake);
        }
    }

    writer.Key("status");
    writer.String("OK");

    writer.Key("address");
    writer.String(address);

    writer.Key("voting_power");
    writer.Uint64(votingPower);

    writer.Key("stake_count");
    writer.Uint64(userStakes.size());

    writer.Key("stakes");
    writer.StartArray();

    for (const auto &stake : userStakes)
    {
        writer.StartObject();

        writer.Key("staking_tx_hash");
        writer.String(stake.stakingTxHash);

        writer.Key("amount");
        writer.Uint64(stake.amount);

        writer.Key("lock_duration_days");
        writer.Uint64(stake.lockDurationDays);

        /* Calculate multiplier */
        uint64_t multiplier = 1;
        if (stake.lockDurationDays >= 360)
            multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_360_DAYS;
        else if (stake.lockDurationDays >= 180)
            multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_180_DAYS;
        else if (stake.lockDurationDays >= 90)
            multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_90_DAYS;
        else if (stake.lockDurationDays >= 30)
            multiplier = Pastella::parameters::governance::LOCK_MULTIPLIER_30_DAYS;

        writer.Key("multiplier");
        writer.Uint64(multiplier);

        writer.Key("voting_power");
        writer.Uint64(stake.amount * multiplier);

        writer.Key("unlock_time");
        writer.Uint64(stake.unlockTime);

        writer.EndObject();
    }

    writer.EndArray();
    writer.EndObject();

    res.body = sb.GetString();

    return {SUCCESS, 200};
}
