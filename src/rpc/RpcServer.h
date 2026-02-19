// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <future>
#include <memory>
#include <optional>
#include <string>

#include "httplib.h"
#include "JsonHelper.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <pastellacore/Core.h>
#include <pastellacore/StakingSystem.h>
#include <pastellaprotocol/PastellaProtocolHandlerCommon.h>
#include <errors/Errors.h>
#include <p2p/NetNode.h>

enum class RpcMode
{
    Default = 0,
    BlockExplorerEnabled = 1,
    AllMethodsEnabled = 2,
};

class RpcServer
{
  public:

    ////////////////////////////////
    /* Constructors / Destructors */
    ////////////////////////////////
    RpcServer(
        const uint16_t bindPort,
        const std::string rpcBindIp,
        const std::string corsHeader,
        const std::string feeAddress,
        const uint64_t feeAmount,
        const RpcMode rpcMode,
        const std::shared_ptr<Pastella::Core> core,
        const std::shared_ptr<Pastella::NodeServer> p2p,
        const std::shared_ptr<Pastella::IPastellaProtocolHandler> syncManager);

    ~RpcServer();

    /////////////////////////////
    /* Public member functions */
    /////////////////////////////

    /* Starts the server. */
    void start();

    /* Stops the server. */
    void stop();

    /* Gets the IP/port combo the server is running on */
    std::tuple<std::string, uint16_t> getConnectionInfo();

  private:
    //////////////////////////////
    /* Private member functions */
    //////////////////////////////

    /* Starts listening for requests on the server */
    void listen();

    std::optional<rapidjson::Document> getJsonBody(
        const httplib::Request &req,
        httplib::Response &res,
        const bool bodyRequired);

    /* Handles stuff like parsing json and then forwards onto the handler */
    void middleware(
        const httplib::Request &req,
        httplib::Response &res,
        const RpcMode routePermissions,
        const bool bodyRequired,
        const bool syncRequired,
        std::function<std::tuple<Error, uint16_t>(
            const httplib::Request &req,
            httplib::Response &res,
            const rapidjson::Document &body)> handler);

    void failRequest(uint16_t statusCode, std::string body, httplib::Response &res);

    void failJsonRpcRequest(
        const int64_t errorCode,
        const std::string errorMessage,
        httplib::Response &res);

    /////////////////////
    /* OPTION REQUESTS */
    /////////////////////

    void handleOptions(const httplib::Request &req, httplib::Response &res) const;

    //////////////////
    /* GET REQUESTS */
    //////////////////

    std::tuple<Error, uint16_t>
        info(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        fee(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        height(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        peers(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    ///////////////////
    /* POST REQUESTS */
    ///////////////////

    std::tuple<Error, uint16_t>
        sendTransaction(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    /* GLOBAL INDEX TRACKING REMOVED - getRandomOuts removed - Ring signature mixing not used in transparent system */

    std::tuple<Error, uint16_t>
        getWalletSyncData(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    /* GLOBAL INDEX TRACKING REMOVED - getGlobalIndexes and getGlobalIndexesDeprecated removed - Global indexes not tracked */

    std::tuple<Error, uint16_t>
        queryBlocksLite(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getTransactionsStatus(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getPoolChanges(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        queryBlocksDetailed(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    /* GLOBAL INDEX TRACKING REMOVED - getGlobalIndexesDeprecated removed */

    std::tuple<Error, uint16_t>
        getRawBlocks(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    ///////////////////////
    /* JSON RPC REQUESTS */
    ///////////////////////

    std::tuple<Error, uint16_t>
        getBlockTemplate(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        submitBlock(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getBlockCount(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getBlockHashForHeight(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getLastBlockHeader(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getBlockHeaderByHash(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getBlockHeaderByHeight(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getBlocksByHeight(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getBlockDetailsByHash(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getTransactionDetailsByHash(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getRichList(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getWalletDetails(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getTransactionsInPool(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getRawTransaction(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    /* UTXO SYSTEM: Get all UTXOs in network with pagination */
    std::tuple<Error, uint16_t>
        getUtxos(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    /* Staking RPC Methods */
    std::tuple<Error, uint16_t>
        getStakingPoolInfo(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getPendingRewards(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getUserStakes(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getAllStakes(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    /* UTXO SYSTEM: UTXO query RPC methods for wallet integration */
    std::tuple<Error, uint16_t>
        getUtxo(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getUtxosForTransaction(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    /* Governance RPC Methods */
    std::tuple<Error, uint16_t>
        getGovernanceProposals(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getProposalDetails(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        createProposal(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getNextProposalId(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        castVote(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    std::tuple<Error, uint16_t>
        getVotingPower(const httplib::Request &req, httplib::Response &res, const rapidjson::Document &body);

    //////////////////////////////
    /* Private member variables */
    //////////////////////////////

    /* Our server instance */
    httplib::Server m_server;

    /* The server host */
    const std::string m_host;

    /* The server port */
    const uint16_t m_port;

    /* The header to use with 'Access-Control-Allow-Origin'. If empty string,
     * header is not added. */
    const std::string m_corsHeader;

    /* The thread running the server */
    std::thread m_serverThread;

    /* The address to return from the /fee endpoint */
    const std::string m_feeAddress;

    /* The amount to return from the /fee endpoint */
    const uint64_t m_feeAmount;

    /* RPC methods that are enabled */
    const RpcMode m_rpcMode;

    /* A pointer to our Pastella instance */
    const std::shared_ptr<Pastella::Core> m_core;

    /* A pointer to our P2P stack */
    const std::shared_ptr<Pastella::NodeServer> m_p2p;

    const std::shared_ptr<Pastella::IPastellaProtocolHandler> m_syncManager;
};