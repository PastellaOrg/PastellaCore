// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The Karai Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2019, The CyprusCoin Developers
//
// Please see the included LICENSE file for more information.

#include "DaemonCommandsHandler.h"
#include "DaemonConfiguration.h"
#include "common/PastellaTools.h"
#include "common/FileSystemShim.h"
#include "common/PathTools.h"
#include "common/ScopeExit.h"
#include "common/SignalHandler.h"
#include "common/StdInputStream.h"
#include "common/StdOutputStream.h"
#include "common/Util.h"
#include "crypto/hash.h"
#include "crypto/hash-ops.h"
#include "pastellacore/Core.h"
#include "pastellacore/Currency.h"
#include "pastellacore/DatabaseBlockchainCache.h"
#include "pastellacore/DatabaseBlockchainCacheFactory.h"
#include "pastellacore/MainChainStorage.h"
#if defined (USE_LEVELDB)
#include "pastellacore/LevelDBWrapper.h"
#else
#include "pastellacore/RocksDBWrapper.h"
#endif
#include "pastellaprotocol/PastellaProtocolHandler.h"
#include "p2p/NetNode.h"
#include "p2p/NetNodeConfig.h"
#include "rpc/RpcServer.h"
#include "serialization/BinaryInputStreamSerializer.h"
#include "serialization/BinaryOutputStreamSerializer.h"

#include <common/FileSystemShim.h>
#include <config/CliHeader.h>
#include <config/PastellaCheckpoints.h>
#include <logging/LoggerManager.h>
#include <logger/Logger.h>
#include <functional>

#if defined(WIN32)

#undef ERROR
#include <crtdbg.h>
#include <io.h>

#else
#include <unistd.h>
#endif

using Common::JsonValue;
using namespace Pastella;
using namespace Logging;
using namespace DaemonConfig;
using Logging::LoggerRef;

void print_genesis_tx_hex(const bool blockExplorerMode, std::shared_ptr<LoggerManager> logManager)
{
    Pastella::CurrencyBuilder currencyBuilder(logManager);
    currencyBuilder.isBlockexplorer(blockExplorerMode);

    Pastella::Currency currency = currencyBuilder.currency();

    const auto transaction = Pastella::CurrencyBuilder(logManager).generateGenesisTransaction();

    std::string transactionHex = Common::toHex(Pastella::toBinaryArray(transaction));
    std::cout << getProjectCLIHeader() << std::endl
              << std::endl
              << "Replace the current GENESIS_COINBASE_TX_HEX line in src/config/PastellaConfig.h with this one:"
              << std::endl
              << "const char GENESIS_COINBASE_TX_HEX[] = \"" << transactionHex << "\";" << std::endl;

    return;
}

JsonValue buildLoggerConfiguration(Level level, const std::string &logfile)
{
    JsonValue loggerConfiguration(JsonValue::OBJECT);
    loggerConfiguration.insert("globalLevel", static_cast<int64_t>(level));

    JsonValue &cfgLoggers = loggerConfiguration.insert("loggers", JsonValue::ARRAY);

    JsonValue &fileLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
    fileLogger.insert("type", "file");
    fileLogger.insert("filename", logfile);
    fileLogger.insert("level", static_cast<int64_t>(TRACE));

    JsonValue &consoleLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
    consoleLogger.insert("type", "console");
    consoleLogger.insert("level", static_cast<int64_t>(TRACE));
    consoleLogger.insert("pattern", "%D %T %L %C ");

    return loggerConfiguration;
}

int main(int argc, char *argv[])
{
    fs::path temp = fs::path(argv[0]).filename();
    DaemonConfiguration config = initConfiguration(temp.string().c_str());

#ifdef WIN32
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    const auto logManager = std::make_shared<LoggerManager>();
    LoggerRef logger(logManager, "Daemon");

    // Initial loading of CLI parameters
    handleSettings(argc, argv, config);

    if (config.printGenesisTx) // Do we weant to generate the Genesis Tx?
    {
        LoggerRef loggerConfig(logManager, "Daemon.Config");
        loggerConfig(INFO) << "Generating genesis transaction hex";
        print_genesis_tx_hex(false, logManager);
        exit(0);
    }

    // If the user passed in the --config-file option, we need to handle that first
    if (!config.configFile.empty())
    {
        LoggerRef loggerConfig(logManager, "Daemon.Config");
        loggerConfig(INFO) << "Loading configuration from file: " << config.configFile;

        try
        {
            if (updateConfigFormat(config.configFile, config))
            {
                std::cout << std::endl << "Updating daemon configuration format..." << std::endl;
                asFile(config, config.configFile);
            }
        }
        catch (std::runtime_error &e)
        {
            std::cout
                << std::endl
                << "There was an error parsing the specified configuration file. Please check the file and try again:"
                << std::endl
                << e.what() << std::endl;
            exit(1);
        }
        catch (std::exception &e)
        {
            // pass
        }

        try
        {
            handleSettings(config.configFile, config);
        }
        catch (std::exception &e)
        {
            std::cout
                << std::endl
                << "There was an error parsing the specified configuration file. Please check the file and try again"
                << std::endl
                << e.what() << std::endl;
            exit(1);
        }
    }

    // Load in the CLI specified parameters again to overwrite anything from the config file
    handleSettings(argc, argv, config);

    if (config.dumpConfig)
    {
        std::cout << getProjectCLIHeader() << asString(config) << std::endl;
        exit(0);
    }
    else if (!config.outputFile.empty())
    {
        try
        {
            asFile(config, config.outputFile);
            std::cout << getProjectCLIHeader() << "Configuration saved to: " << config.outputFile << std::endl;
            exit(0);
        }
        catch (std::exception &e)
        {
            std::cout << getProjectCLIHeader() << "Could not save configuration to: " << config.outputFile << std::endl
                      << e.what() << std::endl;
            exit(1);
        }
    }

    /* If we were given the resync arg, we're deleting everything */
    if (config.resync)
    {
        LoggerRef loggerData(logManager, "Daemon.Data");
        loggerData(WARNING) << "Resync requested - removing blockchain data";

        std::error_code ec;

        std::vector<std::string> removablePaths = {
            config.dataDirectory + "/" + Pastella::parameters::PASTELLA_BLOCKS_FILENAME,
            config.dataDirectory + "/" + Pastella::parameters::PASTELLA_BLOCKINDEXES_FILENAME,
            config.dataDirectory + "/" + Pastella::parameters::P2P_NET_DATA_FILENAME,
            config.dataDirectory + "/DB"};

        for (const auto path : removablePaths)
        {
            loggerData(INFO) << "Removing path: " << path;
            fs::remove_all(fs::path(path), ec);

            if (ec)
            {
                std::cout << "Could not delete data path: " << path << std::endl;
                exit(1);
            }
        }

        loggerData(INFO) << "Blockchain data removed successfully";
    }

    if (config.p2pPort < 0 || config.p2pPort > 65535)
    {
        std::cout << "P2P Port must be between 0 and 65,535" << std::endl;
        exit(1);
    }

    if (config.p2pExternalPort < 0 || config.p2pExternalPort > 65535)
    {
        std::cout << "P2P External Port must be between 0 and 65,535" << std::endl;
        exit(1);
    }

    if (config.rpcPort < 0 || config.rpcPort > 65535)
    {
        std::cout << "RPC Port must be between 0 and 65,535" << std::endl;
        exit(1);
    }

    try
    {
        fs::path cwdPath = fs::current_path();
        auto modulePath = cwdPath / temp;
        auto cfgLogFile = fs::path(config.logFile);

        if (cfgLogFile.empty())
        {
            cfgLogFile = modulePath.replace_extension(".log");
        }
        else
        {
            if (!cfgLogFile.has_parent_path())
            {
                cfgLogFile = modulePath.parent_path() / cfgLogFile;
            }
        }

        Level cfgLogLevel = static_cast<Level>(static_cast<int>(Logging::ERROR) + config.logLevel);

        // configure logging
        logManager->configure(buildLoggerConfiguration(cfgLogLevel, cfgLogFile.string()));

        Logger::logger.setLogLevel(Logger::DEBUG);

        /* New logger, for now just passing through messages to old logger */
        Logger::logger.setLogCallback([&logger](
                const std::string prettyMessage,
                const std::string message,
                const Logger::LogLevel level,
                const std::vector<Logger::LogCategory> categories) {
            Logging::Level oldLogLevel;
            std::string logColour;

            if (level == Logger::DEBUG)
            {
                oldLogLevel = Logging::DEBUGGING;
                logColour = Logging::DEFAULT;
            }
            else if (level == Logger::INFO)
            {
                oldLogLevel = Logging::INFO;
                logColour = Logging::DEFAULT;
            }
            else if (level == Logger::WARNING)
            {
                oldLogLevel = Logging::WARNING;
                logColour = Logging::RED;
            }
            else if (level == Logger::FATAL)
            {
                oldLogLevel = Logging::FATAL;
                logColour = Logging::RED;
            }
            /* setLogCallback shouldn't get called if log level is DISABLED */
            else
            {
                throw std::runtime_error("Programmer error @ setLogCallback in Daemon.cpp");
            }

            logger(oldLogLevel, logColour) << message;
        });

        logger(INFO, BRIGHT_MAGENTA) << getProjectCLIHeader() << std::endl;

        logger(INFO) << "Program Working Directory: " << cwdPath;

        LoggerRef loggerStartup(logManager, "Daemon.Startup");

        // create objects and link them
        loggerStartup(INFO) << "Initializing currency";
        Pastella::CurrencyBuilder currencyBuilder(logManager);
        currencyBuilder.isBlockexplorer(config.enableBlockExplorer);

        try
        {
            currencyBuilder.currency();
        }
        catch (std::exception &)
        {
            std::cout << "GENESIS_COINBASE_TX_HEX constant has an incorrect value. Please launch: "
                      << Pastella::COIN_NAME << "d --print-genesis-tx" << std::endl;
            return 1;
        }
        Pastella::Currency currency = currencyBuilder.currency();
        loggerStartup(INFO) << "Currency initialized";

        DataBaseConfig dbConfig;
        dbConfig.init(
            config.dataDirectory,
            config.dbThreads,
            config.dbMaxOpenFiles,
            config.dbWriteBufferSizeMB,
            config.dbReadCacheSizeMB,
            config.enableDbCompression);

        /* If we were told to rewind the blockchain to a certain height
           we will remove blocks until we're back at the height specified */
        if (config.rewindToHeight > 0)
        {
            LoggerRef loggerRewind(logManager, "Daemon.Rewind");
            loggerRewind(INFO) << "Rewinding blockchain to: " << config.rewindToHeight;

            std::unique_ptr<IMainChainStorage> mainChainStorage = createSwappedMainChainStorage(config.dataDirectory, currency);

            mainChainStorage->rewindTo(config.rewindToHeight);

            loggerRewind(INFO) << "Blockchain rewound to: " << config.rewindToHeight;
        }

        bool use_checkpoints = !config.checkPoints.empty();
        Pastella::Checkpoints checkpoints(logManager);

        if (use_checkpoints)
        {
            LoggerRef loggerCheckpoints(logManager, "Daemon.Checkpoints");
            loggerCheckpoints(INFO) << "Loading Checkpoints for faster initial sync";
            if (config.checkPoints == "default")
            {
                for (const auto &cp : Pastella::CHECKPOINTS)
                {
                    checkpoints.addCheckpoint(cp.index, cp.blockId);
                }
                loggerCheckpoints(INFO) << "Loaded " << Pastella::CHECKPOINTS.size() << " default checkpoints";
            }
            else
            {
                loggerCheckpoints(INFO) << "Loading checkpoints from file: " << config.checkPoints;
                bool results = checkpoints.loadCheckpointsFromFile(config.checkPoints);
                if (!results)
                {
                    throw std::runtime_error("Failed to load checkpoints");
                }
                loggerCheckpoints(INFO) << "Checkpoints loaded successfully";
            }
        }

        NetNodeConfig netNodeConfig;
        netNodeConfig.init(
            config.p2pInterface,
            config.p2pPort,
            config.p2pExternalPort,
            config.localIp,
            config.hideMyPort,
            config.dataDirectory,
            config.peers,
            config.exclusiveNodes,
            config.priorityNodes,
            config.seedNodes,
            config.p2pResetPeerstate);

        if (!Tools::create_directories_if_necessary(dbConfig.getDataDir()))
        {
            throw std::runtime_error("Can't create directory: " + dbConfig.getDataDir());
        }
#if defined (USE_LEVELDB)
        LevelDBWrapper database(logManager);
#else
        RocksDBWrapper database(logManager);
#endif
        database.init(dbConfig);
        Tools::ScopeExit dbShutdownOnExit([&database]() { database.shutdown(); });

        if (!DatabaseBlockchainCache::checkDBSchemeVersion(database, logManager))
        {
            dbShutdownOnExit.cancel();
            database.shutdown();

            database.destroy(dbConfig);

            database.init(dbConfig);
            dbShutdownOnExit.resume();
        }

        System::Dispatcher dispatcher;
        loggerStartup(INFO) << "Initializing core";

        std::unique_ptr<IMainChainStorage> tmainChainStorage = createSwappedMainChainStorage(config.dataDirectory, currency);

        const auto ccore = std::make_shared<Pastella::Core>(
            currency,
            logManager,
            std::move(checkpoints),
            dispatcher,
            std::unique_ptr<IBlockchainCacheFactory>(new DatabaseBlockchainCacheFactory(database, logger.getLogger())),
            std::move(tmainChainStorage),
            config.transactionValidationThreads
        );

        ccore->load();

        loggerStartup(INFO) << "Core initialized";

        /* If we rewound the blockchain, reactivate staking stakes to match the target height */
        if (config.rewindToHeight > 0)
        {
            LoggerRef loggerRewind(logManager, "Daemon.Rewind");
            loggerRewind(INFO) << "Reactivating staking stakes for rewind to height " << config.rewindToHeight;

            if (ccore->reactivateStakesForRewind(config.rewindToHeight))
            {
                loggerRewind(INFO) << "Staking stakes successfully reactivated for rewind";
            }
            else
            {
                loggerRewind(INFO) << "No staking stakes needed reactivation for rewind";
            }
        }

        // Initialize RandomX main seed hash with current blockchain height
        try {
            LoggerRef loggerRandomX(logManager, "Daemon.RandomX");
            uint32_t currentHeight = ccore->get_current_blockchain_height();
            uint64_t seedHeight = Crypto::rx_seedheight(currentHeight);
            Crypto::Hash seedHash = ccore->getBlockHashByIndex(seedHeight);

            loggerRandomX(INFO) << "Initializing RandomX with seed hash from height " << seedHeight
                        << " for current blockchain height " << currentHeight;
            loggerRandomX(DEBUGGING) << "RandomX seed hash: " << Common::toHex(std::vector<uint8_t>(seedHash.data, seedHash.data + Crypto::HASH_SIZE));

            // Initialize RandomX main cache with the calculated seed hash
            Crypto::rx_set_main_seedhash(reinterpret_cast<const char*>(seedHash.data), 4);

            // Set global blockchain interface for RandomX seed hash access
            Crypto::g_getBlockHashByIndex = [ccore](uint32_t blockIndex) -> Crypto::Hash {
                return ccore->getBlockHashByIndex(blockIndex);
            };

            loggerRandomX(INFO) << "RandomX main seed hash initialized successfully";
            loggerRandomX(INFO) << "RandomX blockchain interface configured";

            // Force an immediate update to ensure RandomX cache has the correct seed hash
            loggerRandomX(DEBUGGING) << "Forcing immediate RandomX seed hash verification and update";
            loggerRandomX(DEBUGGING) << "Current blockchain height: " << currentHeight << ", should use seed hash from height: " << seedHeight;

            // Double-check by getting the current seed hash and forcing an update
            Crypto::Hash currentSeedHash = ccore->getBlockHashByIndex(seedHeight);
            loggerRandomX(DEBUGGING) << "Forced RandomX seed hash update: " << Common::toHex(std::vector<uint8_t>(currentSeedHash.data, currentSeedHash.data + Crypto::HASH_SIZE));

            // Force update again to ensure it sticks
            Crypto::rx_set_main_seedhash(reinterpret_cast<const char*>(currentSeedHash.data), 4);

            // Give RandomX a moment to update its internal state
            loggerRandomX(DEBUGGING) << "RandomX seed hash update completed, allowing cache to initialize";

            // Clear any secondary cache that might still have old seed hash by forcing regeneration
            loggerRandomX(DEBUGGING) << "Forcing RandomX secondary cache regeneration to match main cache";

            // The next time rx_slow_hash is called with a different seed hash, it will
            // automatically regenerate the secondary cache to match

        } catch (const std::exception &e) {
            LoggerRef loggerRandomX(logManager, "Daemon.RandomX");
            loggerRandomX(ERROR) << "Failed to initialize RandomX main seed hash: " << e.what();
        }

        loggerStartup(INFO) << "RandomX initialization complete, creating protocol handler";

        loggerStartup(INFO) << "Entering main initialization try block...";

        try {
            loggerStartup(INFO) << "About to create PastellaProtocolHandler...";

            const auto cprotocol = std::make_shared<Pastella::PastellaProtocolHandler>(
                currency,
                dispatcher,
                *ccore,
                nullptr,
                logManager
            );

            loggerStartup(INFO) << "Protocol handler created successfully";

            loggerStartup(INFO) << "Creating NodeServer (P2P)...";

            const auto p2psrv = std::make_shared<Pastella::NodeServer>(
                dispatcher,
                *cprotocol,
                logManager
            );

            loggerStartup(INFO) << "NodeServer created successfully";

            std::string corsDomain;

        /* TODO: enable cors should not be a vector */
        if (!config.enableCors.empty()) {
            corsDomain = config.enableCors[0];
        }

        RpcMode rpcMode = RpcMode::Default;

        loggerStartup(INFO) << "Determining RPC mode...";

        if (config.enableBlockExplorerDetailed)
        {
            rpcMode = RpcMode::AllMethodsEnabled;
            loggerStartup(INFO) << "RPC mode: All methods enabled";
        }
        else if (config.enableBlockExplorer)
        {
            rpcMode = RpcMode::BlockExplorerEnabled;
            loggerStartup(INFO) << "RPC mode: Block explorer enabled";
        }
        else
        {
            loggerStartup(INFO) << "RPC mode: Default";
        }

        loggerStartup(INFO) << "Creating RpcServer...";

        RpcServer rpcServer(
            config.rpcPort,
            config.rpcInterface,
            corsDomain,
            config.feeAddress,
            config.feeAmount,
            rpcMode,
            ccore,
            p2psrv,
            cprotocol
        );

        loggerStartup(INFO) << "RpcServer created successfully";

        cprotocol->set_p2p_endpoint(&(*p2psrv));
        loggerStartup(INFO) << "Setting p2p endpoint and initializing p2p server...";

        if (!p2psrv->init(netNodeConfig))
        {
            loggerStartup(ERROR, BRIGHT_RED) << "Failed to initialize p2p server";
            return 1;
        }

        loggerStartup(INFO) << "P2P server initialized successfully";

        // Fire up the RPC Server
        loggerStartup(INFO) << "Starting RPC server on address " << config.rpcInterface << ":" << config.rpcPort;

        loggerStartup(INFO) << "About to call rpcServer.start()...";

        rpcServer.start();

        loggerStartup(INFO) << "RPC server started successfully";

        loggerStartup(INFO) << "Getting RPC connection info...";

        /* Get the RPC IP address and port we are bound to */
        auto [ip, port] = rpcServer.getConnectionInfo();

        loggerStartup(INFO) << "RPC connection info obtained: " << ip << ":" << port;

        /* If we bound the RPC to 0.0.0.0, we can't reach that with a
           standard HTTP client from anywhere. Instead, let's use the
           localhost IP address to reach ourselves */
        if (ip == "0.0.0.0")
        {
            ip = "127.0.0.1";
        }

        DaemonCommandsHandler dch(*ccore, *p2psrv, logManager, ip, port);

        if (!config.noConsole)
        {
            dch.start_handling();
        }

        Tools::SignalHandler::install([&dch] {
            dch.exit({});
            dch.stop_handling();
        });

        LoggerRef loggerRun(logManager, "Daemon.Run");
        loggerRun(INFO) << "Starting p2p net loop";
        p2psrv->run();
        loggerRun(INFO) << "p2p net loop stopped";

        dch.stop_handling();

        // stop components
        loggerRun(INFO) << "Stopping RPC server";
        rpcServer.stop();

        // Clear RandomX blockchain interface before shutdown to prevent crashes
        loggerRun(INFO) << "Cleaning up RandomX blockchain interface";
        Crypto::g_getBlockHashByIndex = nullptr;

        // deinitialize components
        loggerRun(INFO) << "Deinitializing p2p";
        p2psrv->deinit();

        cprotocol->set_p2p_endpoint(nullptr);
        ccore->save();
    }
    catch (const std::exception &e)
    {
        LoggerRef loggerError(logManager, "Daemon.Error");
        loggerError(ERROR, BRIGHT_RED) << "Exception caught: " << e.what();
        return 1;
    }
    catch (...)
    {
        LoggerRef loggerError(logManager, "Daemon.Error");
        loggerError(ERROR, BRIGHT_RED) << "Unknown exception caught";
        return 1;
    }

    logger(INFO) << "Node stopped";
    return 0;
}
