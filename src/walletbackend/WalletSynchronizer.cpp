// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

/////////////////////////////////////////////
#include <walletbackend/WalletSynchronizer.h>
/////////////////////////////////////////////

#include <common/StringTools.h>
#include <common/TransactionExtra.h>
#include <config/Config.h>
#include <config/WalletConfig.h>
#include <crypto/crypto.h>
#include <future>
#include <iostream>
#include <logger/Logger.h>
#include <utilities/ThreadSafeDeque.h>
#include <utilities/ThreadSafeQueue.h>
#include <utilities/Utilities.h>
#include <walletbackend/Constants.h>

///////////////////////////////////
/* CONSTRUCTORS / DECONSTRUCTORS */
///////////////////////////////////

/* Default constructor */
WalletSynchronizer::WalletSynchronizer(): m_shouldStop(false), m_startTimestamp(0), m_startHeight(0)
{
    unsigned int threads = std::thread::hardware_concurrency();

    /* Number of concurrent threads supported.
       If the value is not well defined or not computable, returns 0. */
    if (threads == 0)
    {
        threads = 1;
    }

    m_threadCount = threads;
}

/* Parameterized constructor */
WalletSynchronizer::WalletSynchronizer(
    const std::shared_ptr<Nigel> daemon,
    const uint64_t startHeight,
    const uint64_t startTimestamp,
    const std::shared_ptr<EventHandler> eventHandler,
    unsigned int threadCount):

    m_daemon(daemon),
    m_shouldStop(false),
    m_startHeight(startHeight),
    m_startTimestamp(startTimestamp),
    m_eventHandler(eventHandler),
    m_blockDownloader(daemon, nullptr, startHeight, startTimestamp)
{
    if (threadCount == 0)
    {
        threadCount = 1;
    }

    m_threadCount = threadCount;
}

/* Move constructor */
WalletSynchronizer::WalletSynchronizer(WalletSynchronizer &&old)
{
    /* Call the move assignment operator */
    *this = std::move(old);
}

/* Move assignment operator */
WalletSynchronizer &WalletSynchronizer::operator=(WalletSynchronizer &&old)
{
    /* Stop any running threads */
    stop();

    m_syncThread = std::move(old.m_syncThread);

    m_startTimestamp = std::move(old.m_startTimestamp);
    m_startHeight = std::move(old.m_startHeight);

    m_eventHandler = std::move(old.m_eventHandler);

    m_daemon = std::move(old.m_daemon);

    m_blockDownloader = std::move(old.m_blockDownloader);

    m_subWallets = std::move(old.m_subWallets);

    m_blockProcessingQueue = std::move(old.m_blockProcessingQueue);

    m_processedBlocks = std::move(old.m_processedBlocks);

    m_threadCount = std::move(old.m_threadCount);

    return *this;
}

/* Deconstructor */
WalletSynchronizer::~WalletSynchronizer()
{
    stop();
}

/////////////////////
/* CLASS FUNCTIONS */
/////////////////////

void WalletSynchronizer::mainLoop()
{
    auto lastCheckedLockedTransactions = std::chrono::system_clock::now();

    while (!m_shouldStop)
    {
        const auto blocks = m_blockDownloader.fetchBlocks(Constants::BLOCK_PROCESSING_CHUNK);

        if (!blocks.empty())
        {
            m_blockProcessingQueue.push_back_n(blocks.begin(), blocks.end());

            /* Tell the child threads to wake up */
            m_haveBlocksToProcess.notify_all();

            const size_t chunkSize = blocks.size();

            {
                /* *possibly* should use another mutex here for the different
                    condition variable? I think it's fine since we're only
                    stopping the child threads from aquiring the mutex for
                    a very short time (since the check will fail when not all
                    blocks are available) */
                std::unique_lock<std::mutex> lock(m_mutex);

                m_haveProcessedBlocksToHandle.wait(lock, [&] {
                    if (m_shouldStop)
                    {
                        return true;
                    }

                    /* Wait until all the blocks have been added to the queue */
                    return m_processedBlocks.size() == chunkSize;
                });

                if (m_shouldStop)
                {
                    return;
                }
            }

            /* Nothing else should be pushing to the queue here, since the
               child threads are waiting for a new chunk, so don't need to
               use mutex to access */
            while (!m_processedBlocks.empty_unsafe() && !m_shouldStop)
            {
                const auto [block, ourInputs, arrivalIndex] = m_processedBlocks.top_unsafe();
                completeBlockProcessing(block, ourInputs);
                m_processedBlocks.pop_unsafe();
            }
        }

        /* If we're synced, check any transactions that may be in the pool */
        if (getCurrentScanHeight() >= m_daemon->localDaemonBlockCount() && !m_shouldStop)
        {
            const auto now = std::chrono::system_clock::now();
            const auto timeDiff = now - lastCheckedLockedTransactions;
            if (timeDiff > std::chrono::seconds(15))
            {
                checkLockedTransactions();
                lastCheckedLockedTransactions = now;
            }

            Utilities::sleepUnlessStopping(std::chrono::seconds(5), m_shouldStop);
        }
    }
}

void WalletSynchronizer::blockProcessingThread()
{
    /* Take the max chunk size, split by the threads, divided by 2. So in
       theory, each thread processes 2 chunks. This is to decrease locking,
       while also trying to stop slower threads from delaying the system. */
    size_t chunkSize = Constants::BLOCK_PROCESSING_CHUNK / m_threadCount / 2;

    if (chunkSize == 0)
    {
        chunkSize = 1;
    }

    /* No point splitting into chunks if we're only using 1 thread */
    if (m_threadCount == 1)
    {
        chunkSize = Constants::BLOCK_PROCESSING_CHUNK;
    }

    std::vector<SemiProcessedBlock> processedBlocks;

    while (!m_shouldStop)
    {
        {
            std::unique_lock<std::mutex> lock(m_mutex);

            /* Wait for blocks to be available */
            m_haveBlocksToProcess.wait(lock, [&] {
                if (m_shouldStop)
                {
                    return true;
                }

                return m_blockProcessingQueue.size() > 0;
            });

            if (m_shouldStop)
            {
                return;
            }
        }

        auto chunk = m_blockProcessingQueue.front_n_and_remove(chunkSize);

        /* Process blocks while we've got more to process */
        while (!chunk.empty() && !m_shouldStop)
        {
            for (const auto &[block, arrivalIndex] : chunk)
            {
                Logger::logger.log(
                    "Processing block " + std::to_string(block.blockHeight), Logger::DEBUG, {Logger::SYNC});

                auto ourInputs = processBlockOutputs(block);

                std::unordered_map<Crypto::Hash, std::vector<uint64_t>> globalIndexes;

                for (auto &[publicKey, input] : ourInputs)
                {
                    if (!input.globalOutputIndex)
                    {
                        /* Transparent system: UTXOs are identified by (transactionHash, outputIndex) directly
                         * Use transactionIndex as the output index */

                        Logger::logger.log(
                            "[WALLET_SYNC] Skipping global index fetch for transparent UTXO at tx "
                            + Common::podToHex(input.parentTransactionHash) + " output "
                            + std::to_string(input.transactionIndex),
                            Logger::TRACE,
                            {Logger::SYNC});

                        input.globalOutputIndex = input.transactionIndex;
                    }
                }

                processedBlocks.push_back({block, ourInputs, arrivalIndex});
            }

            chunk = m_blockProcessingQueue.front_n_and_remove(chunkSize);
        }

        /* Push our processed blocks */
        if (!processedBlocks.empty())
        {
            /* Store this chunks worth of blocks */
            m_processedBlocks.push_n(processedBlocks.begin(), processedBlocks.end());

            /* Notify the parent thread we've pushed data to the queue */
            m_haveProcessedBlocksToHandle.notify_all();

            /* Empty the processed blocks */
            processedBlocks.clear();
        }

        /* Then go back to waiting for more data */
    }
}

std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>>
    WalletSynchronizer::processBlockOutputs(const WalletTypes::WalletBlockInfo &block) const
{
    std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> inputs;

    Logger::logger.log(
        "[WALLET_SYNC] processBlockOutputs called for block " + std::to_string(block.blockHeight),
        Logger::DEBUG,
        {Logger::SYNC});

    Logger::logger.log(
        "[WALLET_SYNC] Coinbase transaction exists: " + std::string(block.coinbaseTransaction ? "YES" : "NO"),
        Logger::DEBUG,
        {Logger::SYNC});

    Logger::logger.log(
        "[WALLET_SYNC] Regular transactions count: " + std::to_string(block.transactions.size()),
        Logger::DEBUG,
        {Logger::SYNC});

    if (!Config::config.wallet.skipCoinbaseTransactions && block.coinbaseTransaction)
    {
        Logger::logger.log(
            "[WALLET_SYNC] Processing coinbase transaction...",
            Logger::DEBUG,
            {Logger::SYNC});

        const auto newInputs = processTransactionOutputs(*(block.coinbaseTransaction), block.blockHeight);

        Logger::logger.log(
            "[WALLET_SYNC] Coinbase transaction generated " + std::to_string(newInputs.size()) + " inputs",
            Logger::TRACE,
            {Logger::SYNC});

        inputs.insert(inputs.end(), newInputs.begin(), newInputs.end());
    }

    for (const auto tx : block.transactions)
    {
        const auto newInputs = processTransactionOutputs(tx, block.blockHeight);

        inputs.insert(inputs.end(), newInputs.begin(), newInputs.end());
    }

    Logger::logger.log(
        "[WALLET_SYNC] Total inputs found: " + std::to_string(inputs.size()),
        Logger::TRACE,
        {Logger::SYNC});

    return inputs;
}

void WalletSynchronizer::completeBlockProcessing(
    const WalletTypes::WalletBlockInfo &block,
    const std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> &ourInputs)
{
    const uint64_t walletHeight = m_blockDownloader.getHeight();

    /* Chain forked, invalidate previous transactions */
    if (walletHeight >= block.blockHeight && block.blockHeight != 0)
    {
        Logger::logger.log(
            "Blockchain forked, resolving... (Old height: " + std::to_string(walletHeight)
                + ", new height: " + std::to_string(block.blockHeight) + ")",
            Logger::INFO,
            {Logger::SYNC});

        removeForkedTransactions(block.blockHeight);
    }

    /* Prune old inputs that are out of our 'confirmation' window */
    if (block.blockHeight % Constants::PRUNE_SPENT_INPUTS_INTERVAL == 0
        && block.blockHeight > Constants::PRUNE_SPENT_INPUTS_INTERVAL)
    {
        m_subWallets->pruneSpentInputs(block.blockHeight - Constants::PRUNE_SPENT_INPUTS_INTERVAL);
    }

    BlockScanTmpInfo blockScanInfo = processBlockTransactions(block, ourInputs);

    for (const auto tx : blockScanInfo.transactionsToAdd)
    {
        std::stringstream stream;

        stream << "Adding transaction: " << tx.hash;

        Logger::logger.log(stream.str(), Logger::INFO, {Logger::SYNC, Logger::TRANSACTIONS});

        m_subWallets->addTransaction(tx);
        m_eventHandler->onTransaction.fire(tx);
    }

    for (const auto [publicKey, input] : blockScanInfo.inputsToAdd)
    {
        std::stringstream stream;

        stream << "Adding input: " << input.key;

        Logger::logger.log(stream.str(), Logger::INFO, {Logger::SYNC});

        m_subWallets->storeTransactionInput(publicKey, input);
    }

    /* The input has been spent, discard the key image so we
       don't double spend it */
    for (const auto &keyImageData : blockScanInfo.keyImagesToMarkSpent)
    {
        const auto &publicKey = std::get<0>(keyImageData);
        const auto &parentTxHash = std::get<1>(keyImageData);
        const auto &txIndex = std::get<2>(keyImageData);

        std::stringstream stream;

        stream << "Marking input as spent: parentTx=" << parentTxHash << " index=" << txIndex;

        Logger::logger.log(stream.str(), Logger::INFO, {Logger::SYNC});

        /* TRANSPARENT SYSTEM: Identify UTXO by (parentTransactionHash, transactionIndex) not just key
         * This is necessary because multiple outputs can have the same key! */
        m_subWallets->markInputAsSpent(publicKey, parentTxHash, txIndex, block.blockHeight);
    }

    /* Make sure to do this at the end, once the transactions are fully
       processed! Otherwise, we could miss a transaction depending upon
       when we save */
    m_blockDownloader.dropBlock(block.blockHeight, block.blockHash);

    if (block.blockHeight >= m_daemon->networkBlockCount())
    {
        m_eventHandler->onSynced.fire(block.blockHeight);
    }

    Logger::logger.log("Finished processing block " + std::to_string(block.blockHeight), Logger::DEBUG, {Logger::SYNC});
}

BlockScanTmpInfo WalletSynchronizer::processBlockTransactions(
    const WalletTypes::WalletBlockInfo &block,
    const std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> &inputs) const
{
    BlockScanTmpInfo txData;

    if (!Config::config.wallet.skipCoinbaseTransactions)
    {
        const auto tx = processCoinbaseTransaction(block, inputs);

        if (tx)
        {
            txData.transactionsToAdd.push_back(*tx);
        }
    }

    for (const auto rawTX : block.transactions)
    {
        const auto result = processTransaction(block, inputs, rawTX);
        const auto &tx = std::get<0>(result);
        const auto &keyImagesToMarkSpent = std::get<1>(result);

        if (tx)
        {
            txData.transactionsToAdd.push_back(*tx);

            txData.keyImagesToMarkSpent.insert(
                txData.keyImagesToMarkSpent.end(), keyImagesToMarkSpent.begin(), keyImagesToMarkSpent.end());
        }
    }

    txData.inputsToAdd = inputs;

    return txData;
}

std::optional<WalletTypes::Transaction> WalletSynchronizer::processCoinbaseTransaction(
    const WalletTypes::WalletBlockInfo &block,
    const std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> &inputs) const
{
    const auto tx = *(block.coinbaseTransaction);

    std::unordered_map<Crypto::PublicKey, int64_t> transfers;

    std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> relevantInputs;

    std::copy_if(inputs.begin(), inputs.end(), std::back_inserter(relevantInputs), [&](const auto input) {
        return std::get<1>(input).parentTransactionHash == tx.hash;
    });

    for (const auto &inputTuple : relevantInputs)
    {
        const auto &publicKey = std::get<0>(inputTuple);
        const auto &input = std::get<1>(inputTuple);
        transfers[publicKey] += input.amount;
    }

    if (!transfers.empty())
    {
        const uint64_t fee = 0;
        const bool isCoinbaseTransaction = true;

        return WalletTypes::Transaction(
            transfers,
            tx.hash,
            fee,
            block.blockTimestamp,
            block.blockHeight,
            tx.unlockTime,
            isCoinbaseTransaction);
    }

    return std::nullopt;
}

/* TRANSPARENT SYSTEM: Return spent inputs identified by (publicKey, parentTransactionHash, transactionIndex) */
std::tuple<std::optional<WalletTypes::Transaction>, std::vector<std::tuple<Crypto::PublicKey, Crypto::Hash, uint64_t>>>
    WalletSynchronizer::processTransaction(
        const WalletTypes::WalletBlockInfo &block,
        const std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> &inputs,
        const WalletTypes::RawTransaction &tx) const
{
    std::unordered_map<Crypto::PublicKey, int64_t> transfers;

    std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> relevantInputs;

    std::copy_if(inputs.begin(), inputs.end(), std::back_inserter(relevantInputs), [&](const auto input) {
        return std::get<1>(input).parentTransactionHash == tx.hash;
    });

    for (const auto &inputTuple : relevantInputs)
    {
        const auto &publicKey = std::get<0>(inputTuple);
        const auto &input = std::get<1>(inputTuple);
        transfers[publicKey] += input.amount;
    }

    /* TRANSPARENT SYSTEM: Track spent inputs by (publicKey, parentTransactionHash, transactionIndex)
     * IMPORTANT: Multiple outputs can have the same key, so we must identify by
     * (parentTransactionHash, transactionIndex) not just by key! */
    std::vector<std::tuple<Crypto::PublicKey, Crypto::Hash, uint64_t>> spentKeyImages;

    /* TRANSPARENT SYSTEM: Detect when wallet's UTXOs are being spent
     *
     * In transparent system, each KeyInput explicitly identifies which UTXO it spends:
     * - KeyInput.transactionHash = hash of transaction that created the UTXO
     * - KeyInput.outputIndex = index of output in that transaction
     *
     * We need to check if any KeyInput is spending one of our wallet's UTXOs.
     * IMPORTANT: Must check ALL stored inputs, not just inputs from current block!
     * Getting all spendable inputs from wallet to properly detect outgoing transactions. */

    /* Get ALL stored wallet inputs (not just current block) to detect outgoing transactions */
    const std::vector<WalletTypes::TxInputAndOwner> allWalletInputs =
        m_subWallets->getSpendableTransactionInputs(true, {}, block.blockHeight);

    std::stringstream ss;
    ss << "Checking TX " << tx.hash << " with " << tx.keyInputs.size()
       << " inputs against " << allWalletInputs.size() << " wallet inputs at height "
       << block.blockHeight;

    Logger::logger.log(ss.str(), Logger::TRACE, {Logger::SYNC});

    Logger::logger.log(
        "[WALLET_SYNC] Checking " + std::to_string(tx.keyInputs.size()) + " KeyInputs against " +
        std::to_string(allWalletInputs.size()) + " stored wallet inputs",
        Logger::TRACE,
        { Logger::SYNC });

    for (const auto &keyInput : tx.keyInputs)
    {
        std::stringstream ss2;
        ss2 << "KeyInput spending: parent=" << Common::podToHex(keyInput.transactionHash)
            << " index=" << keyInput.outputIndex << " amount=" << keyInput.amount;

        Logger::logger.log(ss2.str(), Logger::TRACE, {Logger::SYNC});

        /* Search for a matching wallet input that this KeyInput is spending
         * Check against ALL stored inputs, not just current block inputs */
        for (const auto &walletInputOwner : allWalletInputs)
        {
            const auto &walletInput = walletInputOwner.input;

            /* Check if this KeyInput is spending our wallet's UTXO
             * Match by: parentTransactionHash AND transactionIndex */
            if (walletInput.parentTransactionHash == keyInput.transactionHash &&
                walletInput.transactionIndex == keyInput.outputIndex)
            {
                /* Found a spend! This transaction is spending one of our UTXOs */

                std::stringstream ss3;
                ss3 << "DETECTED SPEND: TX hash=" << tx.hash
                    << " spending UTXO: parent=" << Common::podToHex(keyInput.transactionHash)
                    << " index=" << keyInput.outputIndex
                    << " amount=" << keyInput.amount
                    << " key=" << walletInput.key
                    << " height=" << block.blockHeight;

                Logger::logger.log(ss3.str(), Logger::INFO, {Logger::SYNC});

                Logger::logger.log(
                    "[WALLET_SYNC] Detected spend of UTXO: " + Common::podToHex(keyInput.transactionHash) +
                    " output " + std::to_string(keyInput.outputIndex) +
                    " amount " + std::to_string(keyInput.amount) +
                    " owned by " + Common::podToHex(walletInputOwner.publicKey),
                    Logger::DEBUG,
                    { Logger::SYNC });

                /* Subtract the spent amount from transfers
                 * (Negative amount means money is leaving the wallet) */
                transfers[walletInputOwner.publicKey] -= keyInput.amount;

                /* Mark as spent - PASS parentTransactionHash and transactionIndex to uniquely identify UTXO
                 * In transparent system, multiple outputs can have the same key, so we must identify by
                 * (parentTransactionHash, transactionIndex) not just by key! */
                spentKeyImages.push_back({walletInputOwner.publicKey, walletInput.parentTransactionHash, walletInput.transactionIndex});

                /* Found the match, no need to check other inputs for this KeyInput */
                break;
            }
        }
    }

    Logger::logger.log(
        "TX " + Common::podToHex(tx.hash) + " has " + std::to_string(spentKeyImages.size()) + " spent inputs",
        Logger::TRACE,
        {Logger::SYNC});

    if (!transfers.empty())
    {
        uint64_t fee = 0;

        for (const auto input : tx.keyInputs)
        {
            fee += input.amount;
        }

        for (const auto output : tx.keyOutputs)
        {
            fee -= output.amount;
        }

        const bool isCoinbaseTransaction = false;

        /* Detect if this is a staking transaction by examining extra data */
        bool isStakingTransaction = Pastella::isStakingTransaction(tx.extra);

        /* For staking transactions, extract the actual unlock time from staking extra data */
        uint64_t actualUnlockTime = tx.unlockTime;
        if (isStakingTransaction) {
            Pastella::TransactionExtraStaking stakingData;
            if (Pastella::getStakingDataFromExtra(tx.extra, stakingData)) {
                actualUnlockTime = stakingData.unlockTime;
            }
        }

        const auto newTX = WalletTypes::Transaction(
            transfers,
            tx.hash,
            fee,
            block.blockTimestamp,
            block.blockHeight,
            actualUnlockTime,
            isCoinbaseTransaction,
            isStakingTransaction);

        return {newTX, spentKeyImages};
    }

    return {std::nullopt, {}};
}

std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> WalletSynchronizer::processTransactionOutputs(
    const WalletTypes::RawCoinbaseTransaction &rawTX,
    const uint64_t blockHeight) const
{
    std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> inputs;

    /* TRANSPARENT SYSTEM: Direct key comparison (no derivation needed!)
     * In transparent system, outputs go directly to public keys.
     * No key derivation, no stealth addresses, no privacy! */

    Logger::logger.log(
        "[WALLET_SYNC] processTransactionOutputs called for coinbase",
        Logger::DEBUG,
        {Logger::SYNC});

    Logger::logger.log(
        "[WALLET_SYNC] Output count: " + std::to_string(rawTX.keyOutputs.size()),
        Logger::DEBUG,
        {Logger::SYNC});

    /* For RawCoinbaseTransaction, use the standard unlock time (no staking data available) */
    uint64_t actualUnlockTime = rawTX.unlockTime;

    const std::vector<Crypto::PublicKey> keys = m_subWallets->m_publicKeys;

    Logger::logger.log(
        "[WALLET_SYNC] Wallet has " + std::to_string(keys.size()) + " keys",
        Logger::DEBUG,
        {Logger::SYNC});

    for (const auto &key : keys)
    {
        Logger::logger.log(
            "[WALLET_SYNC] Wallet has key: " + Common::podToHex(key),
            Logger::DEBUG,
            {Logger::SYNC});
    }

    uint64_t outputIndex = 0;

    for (const auto output : rawTX.keyOutputs)
    {
        /* TRANSPARENT SYSTEM: Direct output matching
         * No key derivation needed - simple and transparent! */

        Logger::logger.log(
            "[WALLET_SYNC] Output #" + std::to_string(outputIndex) + " key: " + Common::podToHex(output.key),
            Logger::DEBUG,
            {Logger::SYNC});

        Logger::logger.log(
            "[WALLET_SYNC] Checking if output #" + std::to_string(outputIndex) + " belongs to wallet...",
            Logger::DEBUG,
            {Logger::SYNC});

        bool found = false;

        for (const auto publicKey : keys)
        {
            /* Direct comparison: does this output go to one of our addresses? */
            if (output.key == publicKey)
            {
                Logger::logger.log(
                    "[WALLET_SYNC] ✓✓✓ MATCH FOUND! Output #" + std::to_string(outputIndex) + " belongs to wallet!",
                    Logger::DEBUG,
                    {Logger::SYNC});

                found = true;
                break;
            }
        }

        if (found)
        {
            const auto [error, privateKey, walletIndex] = m_subWallets->getPrivateKey(output.key);

            if (!error)
            {
                /* TRANSPARENT SYSTEM: Unique key images per UTXO
                 * Like Bitcoin, each UTXO is uniquely identified by (txHash, outputIndex).
                 *
                 * To ensure unique key images when multiple outputs go to the same address,
                 * we simply hash the UTXO identifier and use that hash directly as a secret key.
                 *
                 * KeyImage = hash(outputKey) * hash(txHash || outputIndex)
                 *
                 * This guarantees uniqueness because different (txHash, outputIndex) pairs
                 * hash to different values! */

                /* Prepare data to hash: txHash || outputIndex */
                std::vector<uint8_t> utxoIdentifier;
                utxoIdentifier.insert(utxoIdentifier.end(), rawTX.hash.data, rawTX.hash.data + sizeof(rawTX.hash.data));

                /* Add output index */
                uint8_t indexBytes[sizeof(uint64_t)];
                uint64_t outputIndex64 = static_cast<uint64_t>(outputIndex);
                std::memcpy(indexBytes, &outputIndex64, sizeof(uint64_t));
                utxoIdentifier.insert(utxoIdentifier.end(), indexBytes, indexBytes + sizeof(uint64_t));

                /* Hash to get a unique secret key for this UTXO */
                Crypto::Hash utxoHash;
                Crypto::cn_fast_hash(utxoIdentifier.data(), utxoIdentifier.size(), utxoHash);

                /* Use the hash directly as a secret key (after Ed25519 clamping) */
                Crypto::SecretKey utxoSecretKey;
                std::memcpy(&utxoSecretKey, &utxoHash, sizeof(Crypto::Hash));

                /* Clamp to ensure valid Ed25519 scalar */
                reinterpret_cast<uint8_t*>(&utxoSecretKey)[0] &= 248;
                reinterpret_cast<uint8_t*>(&utxoSecretKey)[31] &= 127;
                reinterpret_cast<uint8_t*>(&utxoSecretKey)[31] |= 64;

                /* STEALTH ADDRESS REMOVAL: Key image generation removed
                 * TODO: Phase B - Implement transparent UTXO tracking */
                Logger::logger.log(
                    "[WALLET_SYNC] Processing UTXO at tx:" + Common::podToHex(rawTX.hash) +
                    " output:" + std::to_string(outputIndex),
                    Logger::DEBUG,
                    {Logger::SYNC});

                const uint64_t spendHeight = 0;

                /* STEALTH ADDRESS REMOVAL: TransactionInput initialization updated
                 * keyImage and privateKey fields removed */
                const WalletTypes::TransactionInput input = {
                    output.amount,                           /* amount */
                    blockHeight,                             /* blockHeight */
                    rawTX.transactionPublicKey,              /* transactionPublicKey */
                    outputIndex,                             /* transactionIndex */
                    output.globalOutputIndex,                /* globalOutputIndex */
                    output.key,                              /* key */
                    spendHeight,                             /* spendHeight */
                    actualUnlockTime,                        /* unlockTime */
                    rawTX.hash                               /* parentTransactionHash */
                };

                inputs.emplace_back(output.key, input);
            }
        }

        outputIndex++;
    }

    Logger::logger.log(
        "[WALLET_SYNC] Total inputs found: " + std::to_string(inputs.size()),
        Logger::TRACE,
        {Logger::SYNC});

    return inputs;
}

/* Overloaded method for RawTransaction - handles staking unlock times correctly */
std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> WalletSynchronizer::processTransactionOutputs(
    const WalletTypes::RawTransaction &rawTX,
    const uint64_t blockHeight) const
{
    std::vector<std::tuple<Crypto::PublicKey, WalletTypes::TransactionInput>> inputs;

    // Extract the correct transaction public key from extra data
    Crypto::PublicKey extractedTxPubKey = Pastella::getTransactionPublicKeyFromExtra(rawTX.extra);

    // **THE FIX**: Override the daemon's potentially corrupted transaction public key with the correct one from extra data
    Crypto::PublicKey correctTxPublicKey = (extractedTxPubKey != Crypto::PublicKey()) ? extractedTxPubKey : rawTX.transactionPublicKey;

    bool isStakingTransaction = Pastella::isStakingTransaction(rawTX.extra);

    /* Detect if this is a staking transaction and extract proper unlock time */
    uint64_t actualUnlockTime = rawTX.unlockTime;

    if (isStakingTransaction) {
        Pastella::TransactionExtraStaking stakingData;
        if (Pastella::getStakingDataFromExtra(rawTX.extra, stakingData)) {
            actualUnlockTime = stakingData.unlockTime;
        }
    }

    const std::vector<Crypto::PublicKey> keys = m_subWallets->m_publicKeys;

    uint64_t outputIndex = 0;

    for (const auto output : rawTX.keyOutputs)
    {
        /* TRANSPARENT SYSTEM: Direct key comparison (no derivation needed!) */
        Logger::logger.log(
            "[WALLET_SYNC] Output #" + std::to_string(outputIndex) + " key: " + Common::podToHex(output.key),
            Logger::DEBUG,
            {Logger::SYNC});

        Logger::logger.log(
            "[WALLET_SYNC] Checking if output #" + std::to_string(outputIndex) + " belongs to wallet...",
            Logger::DEBUG,
            {Logger::SYNC});

        bool found = false;

        /* Direct comparison: does this output go to one of our addresses? */
        for (const auto publicKey : keys)
        {
            if (output.key == publicKey)
            {
                Logger::logger.log(
                    "[WALLET_SYNC] ✓✓✓ MATCH FOUND! Output #" + std::to_string(outputIndex) + " belongs to wallet!",
                    Logger::DEBUG,
                    {Logger::SYNC});

                found = true;
                break;
            }
        }

        if (found)
        {
            const auto [error, privateKey, walletIndex] = m_subWallets->getPrivateKey(output.key);

            if (!error)
            {
                /* TRANSPARENT SYSTEM: Unique key images per UTXO
                 * Like Bitcoin, each UTXO is uniquely identified by (txHash, outputIndex).
                 *
                 * To ensure unique key images when multiple outputs go to the same address,
                 * we simply hash the UTXO identifier and use that hash directly as a secret key.
                 *
                 * KeyImage = hash(outputKey) * hash(txHash || outputIndex)
                 *
                 * This guarantees uniqueness because different (txHash, outputIndex) pairs
                 * hash to different values! */

                /* Prepare data to hash: txHash || outputIndex */
                std::vector<uint8_t> utxoIdentifier;
                utxoIdentifier.insert(utxoIdentifier.end(), rawTX.hash.data, rawTX.hash.data + sizeof(rawTX.hash.data));

                /* Add output index */
                uint8_t indexBytes[sizeof(uint64_t)];
                uint64_t outputIndex64 = static_cast<uint64_t>(outputIndex);
                std::memcpy(indexBytes, &outputIndex64, sizeof(uint64_t));
                utxoIdentifier.insert(utxoIdentifier.end(), indexBytes, indexBytes + sizeof(uint64_t));

                /* Hash to get a unique secret key for this UTXO */
                Crypto::Hash utxoHash;
                Crypto::cn_fast_hash(utxoIdentifier.data(), utxoIdentifier.size(), utxoHash);

                /* Use the hash directly as a secret key (after Ed25519 clamping) */
                Crypto::SecretKey utxoSecretKey;
                std::memcpy(&utxoSecretKey, &utxoHash, sizeof(Crypto::Hash));

                /* Clamp to ensure valid Ed25519 scalar */
                reinterpret_cast<uint8_t*>(&utxoSecretKey)[0] &= 248;
                reinterpret_cast<uint8_t*>(&utxoSecretKey)[31] &= 127;
                reinterpret_cast<uint8_t*>(&utxoSecretKey)[31] |= 64;

                /* STEALTH ADDRESS REMOVAL: Key image generation removed
                 * TODO: Phase B - Implement transparent UTXO tracking */
                Logger::logger.log(
                    "[WALLET_SYNC] Processing UTXO at tx:" + Common::podToHex(rawTX.hash) +
                    " output:" + std::to_string(outputIndex),
                    Logger::DEBUG,
                    {Logger::SYNC});

                const uint64_t spendHeight = 0;

                /* STEALTH ADDRESS REMOVAL: TransactionInput initialization updated
                 * keyImage and privateKey fields removed */
                const WalletTypes::TransactionInput input = {
                    output.amount,                           /* amount */
                    blockHeight,                             /* blockHeight */
                    rawTX.transactionPublicKey,              /* transactionPublicKey */
                    outputIndex,                             /* transactionIndex */
                    output.globalOutputIndex,                /* globalOutputIndex */
                    output.key,                              /* key */
                    spendHeight,                             /* spendHeight */
                    actualUnlockTime,                        /* unlockTime */
                    rawTX.hash                               /* parentTransactionHash */
                };

                inputs.emplace_back(output.key, input);
            }
        }

        outputIndex++;
    }

    return inputs;
}

/* When we get the global indexes, we pass in a range of blocks, to obscure
   which transactions we are interested in - the ones that belong to us.
   To do this, we get the global indexes for all transactions in a range.

   For example, if we want the global indexes for a transaction in block
   17, we get all the indexes from block 10 to block 20. */
std::unordered_map<Crypto::Hash, std::vector<uint64_t>>
    WalletSynchronizer::getGlobalIndexes(const uint64_t blockHeight) const
{
    uint64_t startHeight = Utilities::getLowerBound(blockHeight, Constants::GLOBAL_INDEXES_OBSCURITY);

    uint64_t endHeight = Utilities::getUpperBound(blockHeight, Constants::GLOBAL_INDEXES_OBSCURITY);

    const auto [success, indexes] = m_daemon->getGlobalIndexesForRange(startHeight, endHeight);

    if (!success)
    {
        return {};
    }

    return indexes;
}

void WalletSynchronizer::checkLockedTransactions()
{
    /* Get the hashes of any locked tx's we have */
    const auto lockedTxHashes = m_subWallets->getLockedTransactionsHashes();

    if (lockedTxHashes.size() != 0)
    {
        Logger::logger.log("Checking locked transactions", Logger::DEBUG, {Logger::TRANSACTIONS});

        /* Transactions that are in the pool - we'll query these again
           next time to see if they have moved */
        std::unordered_set<Crypto::Hash> transactionsInPool;

        /* Transactions that are in a block - don't need to do anything,
           when we get to the block they will be processed and unlocked. */
        std::unordered_set<Crypto::Hash> transactionsInBlock;

        /* Transactions that the daemon doesn't know about - returned to
           our wallet for timeout or other reason */
        std::unordered_set<Crypto::Hash> cancelledTransactions;

        /* Get the status of the locked transactions */
        bool success = m_daemon->getTransactionsStatus(
            lockedTxHashes, transactionsInPool, transactionsInBlock, cancelledTransactions);

        /* Couldn't get info from the daemon, try again later */
        if (!success)
        {
            Logger::logger.log(
                "Failed to get locked transaction information from daemon",
                Logger::WARNING,
                {Logger::TRANSACTIONS, Logger::DAEMON});

            return;
        }

        /* If some transactions have been cancelled, remove them, and their
           inputs */
        if (cancelledTransactions.size() != 0)
        {
            m_subWallets->removeCancelledTransactions(cancelledTransactions);
        }
    }
}

/* Launch the worker thread in the background. It's safest to do this in a
   seperate function, so everything in the constructor gets initialized,
   and if we do any inheritance, things don't go awry. */
void WalletSynchronizer::start()
{
    Logger::logger.log("Starting sync process", Logger::DEBUG, {Logger::SYNC});

    /* Reinit any vars which may have changed if we previously called stop() */
    m_shouldStop = false;

    if (m_daemon == nullptr)
    {
        throw std::runtime_error("Daemon has not been initialized!");
    }

    m_blockDownloader.start();
    m_blockProcessingQueue.start();
    m_processedBlocks.start();

    m_syncThread = std::thread(&WalletSynchronizer::mainLoop, this);

    m_syncThreads.clear();

    for (unsigned int i = 0; i < m_threadCount; i++)
    {
        m_syncThreads.push_back(std::thread(&WalletSynchronizer::blockProcessingThread, this));
    }
}

void WalletSynchronizer::stop()
{
    Logger::logger.log("Stopping sync process", Logger::DEBUG, {Logger::SYNC});

    /* Tell the threads to stop */
    m_shouldStop = true;

    /* Tell the block downloader to stop and wait for it */
    m_blockDownloader.stop();
    m_blockProcessingQueue.stop();
    m_processedBlocks.stop();

    m_haveBlocksToProcess.notify_all();
    m_haveProcessedBlocksToHandle.notify_all();

    m_blockProcessingQueue.clear();
    m_processedBlocks.clear();

    /* Wait for the block downloader thread to finish (if applicable) */
    if (m_syncThread.joinable())
    {
        m_syncThread.join();
    }

    /* Wait for each child thread to finish */
    for (auto &thread : m_syncThreads)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }
}

void WalletSynchronizer::reset(uint64_t startHeight)
{
    /* Reset start height / timestamp */
    m_startHeight = startHeight;
    m_startTimestamp = 0;

    /* Discard downloaded blocks and sync status */
    m_blockDownloader = BlockDownloader(m_daemon, m_subWallets, m_startHeight, m_startTimestamp);

    /* Need to call start in your calling code - We don't call it here so
       you can schedule the start correctly */
}

/* Remove any transactions at this height or above, they were on a forked
   chain */
void WalletSynchronizer::removeForkedTransactions(const uint64_t forkHeight)
{
    m_subWallets->removeForkedTransactions(forkHeight);
}

void WalletSynchronizer::initializeAfterLoad(
    const std::shared_ptr<Nigel> daemon,
    const std::shared_ptr<EventHandler> eventHandler,
    unsigned int threadCount)
{
    m_daemon = daemon;
    m_eventHandler = eventHandler;
    m_blockDownloader.initializeAfterLoad(m_daemon);

    if (threadCount == 0)
    {
        threadCount = 1;
    }

    m_threadCount = threadCount;
}

uint64_t WalletSynchronizer::getCurrentScanHeight() const
{
    return m_blockDownloader.getHeight();
}

void WalletSynchronizer::swapNode(const std::shared_ptr<Nigel> daemon)
{
    m_daemon = daemon;
}

void WalletSynchronizer::fromJSON(const JSONObject &j)
{
    m_startTimestamp = getUint64FromJSON(j, "startTimestamp");
    m_startHeight = getUint64FromJSON(j, "startHeight");

    m_blockDownloader.fromJSON(getObjectFromJSON(j, "transactionSynchronizerStatus"), m_startHeight, m_startTimestamp);
}

void WalletSynchronizer::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();

    writer.Key("transactionSynchronizerStatus");
    m_blockDownloader.toJSON(writer);

    writer.Key("startTimestamp");
    writer.Uint64(m_startTimestamp);

    writer.Key("startHeight");
    writer.Uint64(m_startHeight);

    writer.EndObject();
}

void WalletSynchronizer::setSubWallets(const std::shared_ptr<SubWallets> subWallets)
{
    m_subWallets = subWallets;
    m_blockDownloader.setSubWallets(m_subWallets);
}
