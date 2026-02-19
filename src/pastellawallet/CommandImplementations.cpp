// Portions Copyright (c) 2018-2019, The Catalyst Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

///////////////////////////////////////////////
#include <pastellawallet/CommandImplementations.h>
///////////////////////////////////////////////

#include <config/PastellaConfig.h>
#include <serialization/SerializationTools.h>
#include <config/WalletConfig.h>
#include <errors/ValidateParameters.h>
#include <fstream>
#include <iomanip>
#include <logger/Logger.h>
#include <utilities/Addresses.h>
#include <utilities/ColouredMsg.h>
#include <utilities/FormatTools.h>
#include <utilities/Input.h>
#include <utilities/String.h>
#include <pastellawallet/Commands.h>
#include <pastellawallet/GetInput.h>
#include <pastellawallet/Menu.h>
#include <pastellawallet/Open.h>
#include <pastellawallet/Sync.h>
#include <pastellawallet/Utilities.h>

void changePassword(const std::shared_ptr<WalletBackend> walletBackend)
{
    /* Check the user knows the current password */
    ZedUtilities::confirmPassword(walletBackend, "Confirm your current password: ");

    /* Get a new password for the wallet */
    const std::string newPassword = getWalletPassword(true, "Enter your new password: ");

    /* Change the wallet password */
    Error error = walletBackend->changePassword(newPassword);

    if (error)
    {
        std::cout << WarningMsg("Your password has been changed, but saving "
                                "the updated wallet failed. If you quit without "
                                "saving succeeding, your password may not "
                                "update.")
                  << std::endl;
    }
    else
    {
        std::cout << SuccessMsg("Your password has been changed!") << std::endl;
    }
}

void backup(const std::shared_ptr<WalletBackend> walletBackend)
{
    ZedUtilities::confirmPassword(walletBackend, "Confirm your current password: ");
    printPrivateKeys(walletBackend);
}

void printPrivateKeys(const std::shared_ptr<WalletBackend> walletBackend)
{
    const auto privateKey = walletBackend->getPrimaryAddressPrivateKey();

    const auto [error, mnemonicSeed] = walletBackend->getMnemonicSeed();
    /* In transparent system, private key is always displayed */
    std::cout << NormalMsg("\nPrivate key:\n") << SuccessMsg(privateKey) << "\n";

    if (!error)
    {
        std::cout << NormalMsg("\nMnemonic seed:\n") << SuccessMsg(mnemonicSeed) << "\n";
    }
}

void balance(const std::shared_ptr<WalletBackend> walletBackend)
{
    auto [unlockedBalance, lockedBalance] = walletBackend->getTotalBalance();

    /* Get staking amounts */
    uint64_t stakedBalance = 0;
    try
    {
        /* Get staking transaction hashes from wallet transactions */
        const auto transactions = walletBackend->getTransactions();
        std::vector<std::string> stakingHashes;

        for (const auto& tx : transactions)
        {
            if (tx.isStakingTransaction && tx.totalAmount() < 0)
            {
                stakingHashes.push_back(Common::podToHex(tx.hash));
            }
        }

        if (!stakingHashes.empty())
        {
            const auto stakes = walletBackend->getUserStakesByHashes(stakingHashes);
            for (const auto& stake : stakes)
            {
                stakedBalance += stake.amount;
            }
        }
    }
    catch (...)
    {
        /* If staking query fails, continue with 0 staked balance */
        stakedBalance = 0;
    }
    /* View wallet balance approximation removed - not applicable in transparent system */

    /* Calculate adjusted balances */
    const uint64_t adjustedLockedBalance = (stakedBalance < lockedBalance) ? (lockedBalance - stakedBalance) : 0;
    const uint64_t totalBalance = unlockedBalance + lockedBalance;

    std::cout << "Available balance:    " << SuccessMsg(Utilities::formatAmount(unlockedBalance)) << "\n";

    if (stakedBalance > 0)
    {
        std::cout << "Staked balance:       " << MagentaMsg(Utilities::formatAmount(stakedBalance)) << "\n";
    }

    std::cout << "Locked balance:       " << WarningMsg(Utilities::formatAmount(adjustedLockedBalance))
              << "\nTotal balance:        " << InformationMsg(Utilities::formatAmount(totalBalance)) << "\n";

    std::cout << "[DEBUG] Locked (unconfirmed) balance: " << WarningMsg(Utilities::formatAmount(lockedBalance)) << "\n";
    /* View wallet warning message removed - not applicable in transparent system */

    const auto [walletBlockCount, localDaemonBlockCount, networkBlockCount] = walletBackend->getSyncStatus();

    if (localDaemonBlockCount < networkBlockCount)
    {
        std::cout << InformationMsg("\nYour daemon is not fully synced with "
                                    "the network!\n")
                  << "Your balance may be incorrect until you are fully "
                  << "synced!\n";
    }
    /* Small buffer because wallet height doesn't update instantly like node
       height does */
    else if (walletBlockCount + 1000 < networkBlockCount)
    {
        std::cout << InformationMsg("\nThe blockchain is still being scanned for "
                                    "your transactions.\n")
                  << "Balances might be incorrect whilst this is ongoing.\n";
    }
}

void printHeights(
    const uint64_t localDaemonBlockCount,
    const uint64_t networkBlockCount,
    const uint64_t walletBlockCount)
{
    /* This is the height that the wallet has been scanned to. The blockchain
       can be fully updated, but we have to walk the chain to find our
       transactions, and this number indicates that progress. */
    std::cout << "Wallet blockchain height: ";

    /* Small buffer because wallet height doesn't update instantly like node
       height does */
    if (walletBlockCount + 1000 > networkBlockCount)
    {
        std::cout << SuccessMsg(walletBlockCount);
    }
    else
    {
        std::cout << WarningMsg(walletBlockCount);
    }

    std::cout << "\nLocal blockchain height: ";

    if (localDaemonBlockCount == networkBlockCount)
    {
        std::cout << SuccessMsg(localDaemonBlockCount);
    }
    else
    {
        std::cout << WarningMsg(localDaemonBlockCount);
    }

    std::cout << "\nNetwork blockchain height: " << SuccessMsg(networkBlockCount) << "\n";
}

void printSyncStatus(
    const uint64_t localDaemonBlockCount,
    const uint64_t networkBlockCount,
    const uint64_t walletBlockCount)
{
    std::string networkSyncPercentage = Utilities::get_sync_percentage(localDaemonBlockCount, networkBlockCount) + "%";

    std::string walletSyncPercentage = Utilities::get_sync_percentage(walletBlockCount, networkBlockCount) + "%";

    std::cout << "Network sync status: ";

    if (localDaemonBlockCount == networkBlockCount)
    {
        std::cout << SuccessMsg(networkSyncPercentage) << std::endl;
    }
    else
    {
        std::cout << WarningMsg(networkSyncPercentage) << std::endl;
    }

    std::cout << "Wallet sync status: ";

    /* Small buffer because wallet height is not always completely accurate */
    if (walletBlockCount + 10 > networkBlockCount)
    {
        std::cout << SuccessMsg(walletSyncPercentage) << std::endl;
    }
    else
    {
        std::cout << WarningMsg(walletSyncPercentage) << std::endl;
    }
}

void printSyncSummary(
    const uint64_t localDaemonBlockCount,
    const uint64_t networkBlockCount,
    const uint64_t walletBlockCount)
{
    if (localDaemonBlockCount == 0 && networkBlockCount == 0)
    {
        std::cout << WarningMsg("Uh oh, it looks like you don't have ") << WarningMsg(WalletConfig::daemonName)
                  << WarningMsg(" open!") << std::endl;
    }
    else if (walletBlockCount + 1000 < networkBlockCount && localDaemonBlockCount == networkBlockCount)
    {
        std::cout << InformationMsg("You are synced with the network, but the "
                                    "blockchain is still being scanned for "
                                    "your transactions.")
                  << std::endl
                  << "Balances might be incorrect whilst this is ongoing." << std::endl;
    }
    else if (localDaemonBlockCount == networkBlockCount)
    {
        std::cout << SuccessMsg("Yay! You are synced!") << std::endl;
    }
    else
    {
        std::cout << WarningMsg("Be patient, you are still syncing with the "
                                "network!")
                  << std::endl;
    }
}

void printHashrate(const uint64_t hashrate)
{
    /* Offline node / not responding */
    if (hashrate == 0)
    {
        return;
    }

    std::cout << "Network hashrate: " << SuccessMsg(Utilities::get_mining_speed(hashrate))
              << " (Based on the last local block)" << std::endl;
}

void status(const std::shared_ptr<WalletBackend> walletBackend)
{
    const WalletTypes::WalletStatus status = walletBackend->getStatus();

    /* Print the heights of local, remote, and wallet */
    printHeights(status.localDaemonBlockCount, status.networkBlockCount, status.walletBlockCount);

    std::cout << "\n";

    /* Print the network and wallet sync status in percentage */
    printSyncStatus(status.localDaemonBlockCount, status.networkBlockCount, status.walletBlockCount);

    std::cout << "\n";

    /* Print the network hashrate, based on the last local block */
    printHashrate(status.lastKnownHashrate);

    /* Print the amount of peers we have */
    std::cout << "Peers: " << SuccessMsg(status.peerCount) << "\n\n";

    /* Print a summary of the sync status */
    printSyncSummary(status.localDaemonBlockCount, status.networkBlockCount, status.walletBlockCount);
}

void reset(const std::shared_ptr<WalletBackend> walletBackend)
{
    const uint64_t scanHeight = ZedUtilities::getScanHeight();

    std::cout << std::endl
              << InformationMsg("This process may take some time to complete.") << std::endl
              << InformationMsg("You can't make any transactions during the ") << InformationMsg("process.")
              << std::endl
              << std::endl;

    if (!Utilities::confirm("Are you sure?"))
    {
        return;
    }

    std::cout << InformationMsg("Resetting wallet...") << std::endl;

    const uint64_t timestamp = 0;

    /* Don't want to queue up transaction events, since sync wallet will print
       them out */
    walletBackend->m_eventHandler->onTransaction.pause();

    walletBackend->reset(scanHeight, timestamp);

    syncWallet(walletBackend);

    /* Readd the event handler for new events */
    walletBackend->m_eventHandler->onTransaction.resume();
}

void saveCSV(const std::shared_ptr<WalletBackend> walletBackend)
{
    const auto transactions = walletBackend->getTransactions();

    if (transactions.empty())
    {
        std::cout << WarningMsg("You have no transactions to save to the CSV!\n");
        return;
    }

    std::ofstream csv(WalletConfig::csvFilename);

    if (!csv)
    {
        std::cout << WarningMsg("Couldn't open transactions.csv file for "
                                "saving!")
                  << std::endl
                  << WarningMsg("Ensure it is not open in any other "
                                "application.")
                  << std::endl;
        return;
    }

    std::cout << InformationMsg("Saving CSV file...") << std::endl;

    /* Create CSV header */
    csv << "Timestamp,Block Height,Hash,Amount,In/Out" << std::endl;

    for (const auto tx : transactions)
    {
        const std::string amount = Utilities::formatAmountBasic(std::abs(tx.totalAmount()));

        const std::string direction = tx.totalAmount() > 0 ? "IN" : "OUT";

        csv << Utilities::unixTimeToDate(tx.timestamp) << "," /* Timestamp */
            << tx.blockHeight << "," /* Block Height */
            << tx.hash << "," /* Hash */
            << amount << "," /* Amount */
            << direction /* In/Out */
            << std::endl;
    }

    std::cout << SuccessMsg("CSV successfully written to ") << SuccessMsg(WalletConfig::csvFilename) << SuccessMsg("!")
              << std::endl;
}

void printOutgoingTransfer(const WalletTypes::Transaction tx)
{
    std::stringstream stream;

    const int64_t amount = std::abs(tx.totalAmount());

    // Use the isStakingTransaction flag that is set during wallet synchronization
    bool isStaking = tx.isStakingTransaction;

    if (isStaking)
    {
        stream << "Outgoing transfer: STAKING\n";
    }
    else
    {
        stream << "Outgoing transfer:\n";
    }

    stream << "Hash: " << tx.hash << "\n";

    /* These will not be initialized for outgoing, unconfirmed transactions */
    if (tx.blockHeight != 0 && tx.timestamp != 0)
    {
        stream << "Block height: " << tx.blockHeight << "\n"
               << "Timestamp: " << Utilities::unixTimeToDate(tx.timestamp) << "\n";
    }

    stream << "Spent: " << Utilities::formatAmount(amount - tx.fee) << "\n"
           << "Fee: " << Utilities::formatAmount(tx.fee) << "\n"
           << "Total Spent: " << Utilities::formatAmount(amount) << "\n";

    std::cout << WarningMsg(stream.str()) << std::endl;
}

void printIncomingTransfer(const WalletTypes::Transaction tx)
{
    std::stringstream stream;

    const int64_t amount = tx.totalAmount();

    stream << "Incoming transfer:\nHash: " << tx.hash << "\n"
           << "Block height: " << tx.blockHeight << "\n"
           << "Timestamp: " << Utilities::unixTimeToDate(tx.timestamp) << "\n"
           << "Amount: " << Utilities::formatAmount(amount) << "\n";

    /* Display Unlock time, if applicable; otherwise, don't */
    int64_t difference = tx.unlockTime - tx.blockHeight;

    /* Here we treat Unlock as a block, and treat it that way in the future */
    if (tx.unlockTime != 0 && difference > 0 && tx.unlockTime < Pastella::parameters::PASTELLA_MAX_BLOCK_NUMBER)
    {
        int64_t unlockInUnixTime = tx.timestamp + (difference * Pastella::parameters::DIFFICULTY_TARGET);

        std::cout << SuccessMsg(stream.str()) << InformationMsg("Unlock height: ") << InformationMsg(tx.unlockTime)
                  << std::endl
                  << InformationMsg("Unlocks at approximately: ")
                  << InformationMsg(Utilities::unixTimeToDate(unlockInUnixTime)) << std::endl
                  << std::endl;
    }
    /* Here we treat Unlock as Unix time, and treat it that way in the future */
    else if (tx.unlockTime > static_cast<uint64_t>(std::time(nullptr)))
    {
        std::cout << SuccessMsg(stream.str()) << InformationMsg("Unlocks at: ")
                  << InformationMsg(Utilities::unixTimeToDate(tx.unlockTime)) << std::endl
                  << std::endl;
    }
    else
    {
        std::cout << SuccessMsg(stream.str()) << std::endl;
    }
}

void listTransfers(const bool incoming, const bool outgoing, const std::shared_ptr<WalletBackend> walletBackend)
{
    uint64_t totalSpent = 0;
    uint64_t totalReceived = 0;

    uint64_t numIncomingTransactions = 0;
    uint64_t numOutgoingTransactions = 0;

    /* Grab confirmed transactions */
    std::vector<WalletTypes::Transaction> transactions = walletBackend->getTransactions();

    /* Grab any outgoing transactions still in the pool */
    const auto unconfirmedTransactions = walletBackend->getUnconfirmedTransactions();

    /* Append them, unconfirmed transactions last */
    transactions.insert(transactions.end(), unconfirmedTransactions.begin(), unconfirmedTransactions.end());

    for (const auto tx : transactions)
    {
        const int64_t amount = tx.totalAmount();

        if (amount < 0 && outgoing)
        {
            printOutgoingTransfer(tx);

            totalSpent += -amount;
            numOutgoingTransactions++;
        }
        else if (amount > 0 && incoming)
        {
            printIncomingTransfer(tx);

            totalReceived += amount;
            numIncomingTransactions++;
        }
    }

    std::cout << InformationMsg("Summary:\n\n");

    if (incoming)
    {
        std::cout << SuccessMsg(numIncomingTransactions) << SuccessMsg(" incoming transactions, totalling ")
                  << SuccessMsg(Utilities::formatAmount(totalReceived)) << std::endl;
    }

    if (outgoing)
    {
        std::cout << WarningMsg(numOutgoingTransactions) << WarningMsg(" outgoing transactions, totalling ")
                  << WarningMsg(Utilities::formatAmount(totalSpent)) << std::endl;
    }
}

void save(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Saving.") << std::endl;

    Error error = walletBackend->save();

    if (error)
    {
        std::cout << WarningMsg("Failed to save wallet! Error: ") << WarningMsg(error) << std::endl;
    }
    else
    {
        std::cout << InformationMsg("Saved.") << std::endl;
    }
}

void help(const std::shared_ptr<WalletBackend> walletBackend)
{
    printCommands(basicCommands());
}

void advanced(const std::shared_ptr<WalletBackend> walletBackend)
{
    /* We pass the offset of the command to know what index to print for
       command numbers */
    printCommands(advancedCommands(), basicCommands().size());
}

void swapNode(const std::shared_ptr<WalletBackend> walletBackend)
{
    const auto [host, port, ssl] = getDaemonAddress();

    std::cout << InformationMsg("\nSwapping node, this may take some time...\n");

    walletBackend->swapNode(host, port, ssl);

    std::cout << SuccessMsg("Node swap complete.\n\n");
}

void getTxPrivateKey(const std::shared_ptr<WalletBackend> walletBackend)
{
    const std::string txHash = getHash("What transaction hash do you want to get the private key of?: ", true);

    if (txHash == "cancel")
    {
        return;
    }

    Crypto::Hash hash;

    Common::podFromHex(txHash, hash);

    const auto [error, key] = walletBackend->getTxPrivateKey(hash);

    if (error)
    {
        std::cout << WarningMsg(error) << std::endl;
    }
    else
    {
        std::cout << InformationMsg("Transaction private key: ") << SuccessMsg(key) << std::endl;
    }
}

void setLogLevel()
{
    const std::vector<Command> logLevels = {
        Command("Trace",    "Display extremely detailed logging output"),
        Command("Debug",    "Display highly detailed logging output"),
        Command("Info",     "Display detailed logging output"),
        Command("Warning",  "Display only warning and error logging output"),
        Command("Fatal",    "Display only error logging output"),
        Command("Disabled", "Don't display any logging output"),
    };

    printCommands(logLevels);

    std::string level = parseCommand(logLevels, logLevels, "What log level do you want to use?: ");

    if (level == "exit")
    {
        return;
    }

    Logger::logger.setLogLevel(Logger::stringToLogLevel(level));
}

/* Staking Command Implementations */

void stake(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Create a new staking transaction") << std::endl << std::endl;

    /* Get staking amount */
    const auto [success, amount] = getAmountToAtomic("Enter the amount to stake (in " + WalletConfig::ticker + "): ", true);

    if (!success)
    {
        std::cout << WarningMsg("Cancelling staking transaction.") << std::endl;
        return;
    }

    /* Get lock duration options */
    std::cout << std::endl << InformationMsg("Available lock periods and annual reward rates:") << std::endl;

    for (uint32_t i = 0; i < Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS_COUNT; i++) {
        uint32_t days = Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i];
        uint32_t rate = Pastella::parameters::staking::ANNUAL_REWARD_RATES[i];

        std::cout << "  " << InformationMsg(std::to_string(days) + " days: ")
                  << SuccessMsg(std::to_string(rate) + "% APY") << std::endl;
    }

    std::cout << std::endl;

    /* Get lock duration from user */
    std::cout << "Enter lock period (30/90/180/365 days): ";
    std::string lockPeriodStr;
    std::getline(std::cin, lockPeriodStr);

    if (lockPeriodStr == "exit" || lockPeriodStr == "cancel") {
        std::cout << WarningMsg("Cancelling staking transaction.") << std::endl;
        return;
    }

    /* Validate lock period */
    uint32_t lockDays = 0;
    bool validPeriod = false;
    for (uint32_t i = 0; i < Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS_COUNT; i++) {
        if (std::to_string(Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i]) == lockPeriodStr) {
            lockDays = Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i];
            validPeriod = true;
            break;
        }
    }

    if (!validPeriod) {
        std::cout << WarningMsg("Invalid lock period. Please choose from 30, 90, 180, or 365 days.") << std::endl;
        return;
    }

    /* Automatically use primary address with confirmation */
    std::string address = walletBackend->getPrimaryAddress();

    std::cout << std::endl << InformationMsg("=== Staking Transaction Details ===") << std::endl;
    std::cout << InformationMsg("Amount to stake: ") << SuccessMsg(Utilities::formatAmount(amount) + " " + WalletConfig::ticker) << std::endl;
    std::cout << InformationMsg("Lock period: ") << SuccessMsg(std::to_string(lockDays) + " days") << std::endl;
    std::cout << InformationMsg("Staking address: ") << SuccessMsg(address) << std::endl;

    /* Debug information */
    std::cout << std::endl << "[DEBUG] Using primary address: " << address << std::endl;
    std::cout << "[DEBUG] Amount in atomic units: " << amount << std::endl;
    std::cout << "[DEBUG] Lock duration in days: " << lockDays << std::endl;

    /* Calculate estimated rewards */
    uint32_t ratePerDay = 0;
    for (uint32_t i = 0; i < Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS_COUNT; i++) {
        if (Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i] == lockDays) {
            ratePerDay = Pastella::parameters::staking::ANNUAL_REWARD_RATES[i];
            break;
        }
    }

    if (ratePerDay > 0) {
        double dailyRateDecimal = static_cast<double>(ratePerDay) / 100.0 / 365.0;
        double dailyReward = static_cast<double>(amount) * dailyRateDecimal;
        double yearlyReward = dailyReward * 365.0;

        std::cout << InformationMsg("Estimated daily reward: ") << SuccessMsg(Utilities::formatAmount(static_cast<uint64_t>(dailyReward)) + " " + WalletConfig::ticker) << std::endl;
        std::cout << InformationMsg("Estimated yearly reward: ") << SuccessMsg(Utilities::formatAmount(static_cast<uint64_t>(yearlyReward)) + " " + WalletConfig::ticker) << std::endl;
        std::cout << InformationMsg("APY: ") << SuccessMsg(std::to_string(ratePerDay) + "%") << std::endl;

        std::cout << "[DEBUG] Daily rate (decimal): " << dailyRateDecimal << std::endl;
        std::cout << "[DEBUG] Daily reward (atomic): " << static_cast<uint64_t>(dailyReward) << std::endl;
    }

    /* Confirmation */
    std::cout << std::endl;
    std::cout << WarningMsg("Do you want to proceed with this staking transaction? (y/n): ");
    std::string confirmation;
    std::getline(std::cin, confirmation);
    Utilities::trim(confirmation);

    if (confirmation != "y" && confirmation != "Y") {
        std::cout << WarningMsg("Staking transaction cancelled.") << std::endl;
        return;
    }

    std::cout << std::endl << InformationMsg("Creating staking transaction...") << std::endl;
    std::cout << "[DEBUG] Calling walletBackend->stake()..." << std::endl;

    /* Call wallet backend staking function */
    const auto [error, hash, preparedTransaction, rewardAddress] = walletBackend->stake(amount, lockDays, address);

    if (error) {
        std::cout << WarningMsg("Failed to create staking transaction: ") << error << std::endl;
        std::cout << "[DEBUG] Error details: " << error << std::endl;
        return;
    }

    std::cout << SuccessMsg("Staking transaction created successfully!") << std::endl;
    std::cout << std::endl << InformationMsg("Transaction Details:") << std::endl;
    std::cout << InformationMsg("Transaction Hash: ") << SuccessMsg(Common::podToHex(hash)) << std::endl;
    std::cout << InformationMsg("Amount: ") << SuccessMsg(Utilities::formatAmount(amount)) << " " << WalletConfig::ticker << std::endl;
    std::cout << InformationMsg("Lock Period: ") << SuccessMsg(std::to_string(lockDays) + " days") << std::endl;
    std::cout << InformationMsg("Address: ") << SuccessMsg(address) << std::endl;
}



void listStakes(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Your staking positions") << std::endl << std::endl;

    // Get all transactions and filter for staking transactions
    const auto transactions = walletBackend->getTransactions();
    std::vector<std::string> stakingHashes;

    for (const auto& tx : transactions) {
        if (tx.isStakingTransaction && tx.totalAmount() < 0) { // Outgoing staking transactions
            stakingHashes.push_back(Common::podToHex(tx.hash));
        }
    }

    const auto stakes = walletBackend->getUserStakesByHashes(stakingHashes);

    if (stakes.empty()) {
        std::cout << InformationMsg("You have no active staking positions.") << std::endl;
        return;
    }

    std::cout << std::left
              << std::setw(22) << "Amount"
              << std::setw(6) << "Lock"
              << std::setw(19) << "Earned"
              << std::setw(19) << "Daily"
              << std::setw(16) << "Time Left"
              << std::setw(10) << "Status"
              << "Transaction Hash"
              << std::endl;

    std::cout << std::string(108, '-') << std::endl;

    uint64_t totalDailyRewards = 0;
    uint64_t totalWeeklyRewards = 0;
    uint64_t totalMonthlyRewards = 0;
    uint64_t totalYearlyRewards = 0;
    uint64_t totalEarned = 0;

    for (const auto& stake : stakes) {
        /* Calculate remaining time in days, hours, and minutes */
        std::string remainingTime = "Completed";
        if (stake.isActive && stake.unlockTime > stake.currentHeight) {
            uint64_t remainingBlocks = stake.unlockTime - stake.currentHeight;

            /* Calculate total minutes remaining (30 seconds per block) */
            uint64_t totalMinutes = (remainingBlocks * 30) / 60;

            /* Extract days, hours, minutes */
            uint64_t days = totalMinutes / (24 * 60);
            uint64_t hours = (totalMinutes % (24 * 60)) / 60;
            uint64_t minutes = totalMinutes % 60;

            /* Format as "Xd XXh XXm" */
            remainingTime = std::to_string(days) + "d " +
                           (hours < 10 ? "0" : "") + std::to_string(hours) + "h " +
                           (minutes < 10 ? "0" : "") + std::to_string(minutes) + "m";
        }

        /* Show reasonable block count */
        uint64_t safeBlocksStaked = (stake.blocksStaked > 100000) ? 0 : stake.blocksStaked;

        /* Calculate daily reward manually */
        uint64_t safeDailyReward = 0;
        if (stake.estDailyReward > 1000000000 || stake.blocksStaked > 100000) {
            /* If data looks corrupted, recalculate from scratch using config values */
            uint32_t rate = 0;
            for (size_t i = 0; i < Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS_COUNT; i++) {
                if (stake.lockDurationDays == Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i]) {
                    rate = Pastella::parameters::staking::ANNUAL_REWARD_RATES[i];
                    break;
                }
            }
            if (rate == 0) rate = 5; /* Default to lowest rate if not found */
            safeDailyReward = (stake.amount * rate) / (365 * 100);
        } else {
            safeDailyReward = stake.estDailyReward;
        }

        /* Calculate accumulated earnings using current API data */
        totalEarned += stake.accumulatedEarnings;

        std::cout << std::left
                  << std::setw(22) << Utilities::formatAmount(stake.amount)
                  << std::setw(6) << std::to_string(stake.lockDurationDays) + "d"
                  << std::setw(1) << MagentaMsg(Utilities::formatAmount(stake.accumulatedEarnings))
                  << std::setw(12) << MagentaMsg(Utilities::formatAmount(safeDailyReward))
                  << std::setw(12) << InformationMsg(remainingTime);

        if (stake.isActive) {
            std::cout << std::setw(12) << YellowMsg("Active");
        } else {
            /* Check if staking period has ended by comparing current height with unlock time */
            if (stake.currentHeight >= stake.unlockTime) {
                std::cout << std::setw(12) << SuccessMsg("Ended ");
            } else {
                std::cout << std::setw(12) << InformationMsg("Ready ");
            }
        }

        std::cout << "    " << Common::podToHex(stake.stakingTxHash) << std::endl;

        /* Use the reward estimates from the daemon API (most accurate) */
        totalDailyRewards += stake.estDailyReward;
        totalWeeklyRewards += stake.estWeeklyReward;
        totalMonthlyRewards += stake.estMonthlyReward;
        totalYearlyRewards += stake.estYearlyReward;
    }

    uint64_t totalStaked = 0;
    for (const auto& stake : stakes) {
        totalStaked += stake.amount;
    }

    std::cout << std::endl << InformationMsg("Total Staked: ")
              << SuccessMsg(Utilities::formatAmount(totalStaked)) << std::endl;

    /* Display accumulated earnings */
    std::cout << InformationMsg("Total Earned: ")
              << MagentaMsg(Utilities::formatAmount(totalEarned)) << std::endl << std::endl;

    /* Display reward projections */
    std::cout << InformationMsg("Estimated Rewards: ") << std::endl;

    std::cout << InformationMsg("Daily:   ")
              << MagentaMsg(Utilities::formatAmount(totalDailyRewards)) << std::endl;

    std::cout << InformationMsg("Weekly:  ")
              << MagentaMsg(Utilities::formatAmount(totalWeeklyRewards)) << std::endl;

    std::cout << InformationMsg("Monthly: ")
              << MagentaMsg(Utilities::formatAmount(totalMonthlyRewards)) << std::endl;

    std::cout << InformationMsg("Yearly:  ")
              << MagentaMsg(Utilities::formatAmount(totalYearlyRewards)) << std::endl << std::endl;
}

void stakingInfo(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Staking Information") << std::endl << std::endl;

    std::cout << InformationMsg("Available Lock Periods and Rewards:") << std::endl;

    for (uint32_t i = 0; i < Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS_COUNT; i++) {
        uint32_t days = Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i];
        uint32_t rate = Pastella::parameters::staking::ANNUAL_REWARD_RATES[i];
        uint32_t apy = rate;

        std::cout << "  " << std::right << std::setw(3) << days << " days: "
                  << std::left << std::setw(8) << SuccessMsg(std::to_string(apy) + "% APY")
                  << std::endl;
    }

    std::cout << std::endl;
    std::cout << InformationMsg("Minimum Staking Amount: ")
              << SuccessMsg(Utilities::formatAmount(Pastella::parameters::staking::MIN_STAKING_AMOUNT)) << std::endl;

    std::cout << InformationMsg("Automatic Return: ")
              << SuccessMsg("Funds return to wallet when lock period ends") << std::endl;
}

void calculateRewards(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Calculate potential staking rewards") << std::endl << std::endl;

    /* Get staking amount */
    const auto [success, amount] = getAmountToAtomic("Enter amount to calculate rewards for (in " + WalletConfig::ticker + "): ", true);

    if (!success) {
        std::cout << WarningMsg("Cancelling reward calculation.") << std::endl;
        return;
    }

    std::cout << std::endl << InformationMsg("Potential rewards for " + Utilities::formatAmount(amount) + ":") << std::endl;

    std::cout << std::left
              << std::setw(10) << "Days"
              << std::setw(7) << "APY"
              << std::setw(22) << "Daily Reward"
              << std::setw(20) << "Total Reward"
              << std::endl;

    std::cout << std::string(65, '-') << std::endl;

    for (uint32_t i = 0; i < Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS_COUNT; i++) {
        uint32_t days = Pastella::parameters::staking::MIN_LOCK_PERIOD_DAYS[i];
        uint32_t rate = Pastella::parameters::staking::ANNUAL_REWARD_RATES[i];
        uint32_t apy = rate;

        /* Calculate rewards using annual rate: Daily Reward = Amount × (AnnualRate ÷ 100) ÷ 365 */
        uint64_t dailyReward = (amount * rate) / 365ULL;
        uint64_t totalReward = dailyReward * days;

        std::cout << std::left
                  << std::setw(10) << std::to_string(days)
                  << SuccessMsg(std::to_string(apy) + "%")
                  << std::string(6 - std::to_string(apy).length(), ' ')
                  << std::setw(11) << Utilities::formatAmount(dailyReward)
                  << std::setw(15) << SuccessMsg(Utilities::formatAmount(totalReward))
                  << std::endl;
    }

    std::cout << std::endl;
}

/* Governance command implementations */
/****************************************/

void createProposal(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Create a new governance proposal") << std::endl << std::endl;

    /* Get proposal title */
    std::cout << InformationMsg("Enter proposal title (1-200 characters): ") << std::endl;
    std::string title;
    std::getline(std::cin, title);

    if (title.empty() || title == "exit" || title == "cancel")
    {
        std::cout << WarningMsg("Cancelling proposal creation.") << std::endl;
        return;
    }

    if (title.length() > 200)
    {
        std::cout << WarningMsg("Title too long! Maximum 200 characters.") << std::endl;
        return;
    }

    /* Get proposal description */
    std::cout << std::endl << InformationMsg("Enter proposal description (1-5000 characters):") << std::endl;
    std::cout << InformationMsg("Press ENTER twice when finished:") << std::endl;
    std::string description;
    std::string line;
    while (std::getline(std::cin, line))
    {
        if (line.empty())
        {
            break;
        }
        description += line + "\n";
        if (description.length() > 5000)
        {
            std::cout << WarningMsg("Description too long! Maximum 5000 characters.") << std::endl;
            return;
        }
    }

    if (description.empty())
    {
        std::cout << WarningMsg("Description cannot be empty!") << std::endl;
        return;
    }

    /* Get proposal type */
    std::cout << std::endl << InformationMsg("Select proposal type:") << std::endl;
    std::cout << "  0 - Parameter Change (51% threshold)" << std::endl;
    std::cout << "  1 - Protocol Upgrade (67% threshold)" << std::endl;
    std::cout << "  2 - Treasury Spending (51% threshold)" << std::endl;
    std::cout << std::endl << InformationMsg("Enter proposal type (0/1/2): ");

    std::string typeStr;
    std::getline(std::cin, typeStr);

    uint8_t proposalType = 0;
    if (typeStr == "0")
    {
        proposalType = 0;
    }
    else if (typeStr == "1")
    {
        proposalType = 1;
    }
    else if (typeStr == "2")
    {
        proposalType = 2;
    }
    else
    {
        std::cout << WarningMsg("Invalid proposal type. Cancelling.") << std::endl;
        return;
    }

    /* For treasury proposals, get amount and recipient */
    uint64_t amount = 0;
    std::string recipientAddress = "";

    if (proposalType == 2)
    {
        std::cout << std::endl << InformationMsg("=== Treasury Proposal Details ===") << std::endl;

        /* Get amount */
        std::cout << InformationMsg("Enter amount to request (in PAS, e.g., 1000.5): ") << std::endl;
        std::string amountStr;
        std::getline(std::cin, amountStr);

        try
        {
            double amountDouble = std::stod(amountStr);
            if (amountDouble <= 0)
            {
                std::cout << WarningMsg("Amount must be greater than 0. Cancelling.") << std::endl;
                return;
            }

            /* Convert to atomic units (8 decimal places) */
            amount = static_cast<uint64_t>(amountDouble * 100000000);
        }
        catch (const std::exception &e)
        {
            std::cout << WarningMsg("Invalid amount format. Cancelling.") << std::endl;
            return;
        }

        /* Get recipient address */
        std::cout << InformationMsg("Enter recipient address: ") << std::endl;
        std::getline(std::cin, recipientAddress);
        Utilities::trim(recipientAddress);

        if (recipientAddress.empty())
        {
            std::cout << WarningMsg("Recipient address cannot be empty. Cancelling.") << std::endl;
            return;
        }

        std::cout << std::endl << InformationMsg("Amount: ") << SuccessMsg(Utilities::formatAmount(amount) + " PAS") << std::endl;
        std::cout << InformationMsg("Recipient: ") << SuccessMsg(recipientAddress) << std::endl;
    }

    /* Confirm */
    std::cout << std::endl << InformationMsg("=== Proposal Details ===") << std::endl;
    std::cout << InformationMsg("Title: ") << SuccessMsg(title) << std::endl;
    std::cout << InformationMsg("Description: ") << SuccessMsg(description.substr(0, 100)) << "..." << std::endl;
    std::cout << InformationMsg("Type: ") << SuccessMsg(std::to_string(proposalType)) << std::endl;
    std::cout << std::endl << WarningMsg("Create this proposal? (y/n): ");

    std::string confirm;
    std::getline(std::cin, confirm);
    Utilities::trim(confirm);

    if (confirm != "y" && confirm != "Y")
    {
        std::cout << WarningMsg("Proposal creation cancelled.") << std::endl;
        return;
    }

    /* Create proposal */
    std::cout << std::endl << InformationMsg("Creating proposal...") << std::endl;

    const auto [error, proposalId] = walletBackend->createProposal(title, description, proposalType, amount, recipientAddress);

    if (error != SUCCESS)
    {
        std::cout << WarningMsg("Failed to create proposal: ") << error << std::endl;
        return;
    }

    std::cout << SuccessMsg("Proposal created successfully!") << std::endl;
    std::cout << InformationMsg("Proposal ID: ") << SuccessMsg(proposalId) << std::endl;
}

void listProposals(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Governance Proposals") << std::endl << std::endl;

    const auto [error, proposals] = walletBackend->getGovernanceProposals(false);

    if (error != SUCCESS)
    {
        std::cout << WarningMsg("Failed to get proposals: ") << error << std::endl;
        return;
    }

    if (proposals.empty())
    {
        std::cout << InformationMsg("No proposals found.") << std::endl;
        return;
    }

    for (const auto &proposal : proposals)
    {
        std::cout << InformationMsg("Proposal ID: ") << SuccessMsg(std::to_string(proposal.proposalId)) << std::endl;
        std::cout << InformationMsg("  Title: ") << SuccessMsg(proposal.title) << std::endl;
        std::cout << InformationMsg("  Status: ") << SuccessMsg(proposal.isActive ? "Active" : proposal.result) << std::endl;

        if (proposal.isActive)
        {
            std::cout << InformationMsg("  Votes For: ") << SuccessMsg(Utilities::formatAmount(proposal.votesFor)) << std::endl;
            std::cout << InformationMsg("  Votes Against: ") << SuccessMsg(Utilities::formatAmount(proposal.votesAgainst)) << std::endl;

            uint8_t threshold = 51;
            if (proposal.proposalType == 1)
                threshold = 67;
            else if (proposal.proposalType == 2)
                threshold = 51;

            uint64_t requiredVotes = (proposal.totalVotingPower * threshold) / 100;
            uint64_t percentFor = proposal.totalVotingPower > 0 ? (proposal.votesFor * 100) / proposal.totalVotingPower : 0;

            std::cout << InformationMsg("  Progress: ") << SuccessMsg(std::to_string(percentFor) + "% / " + std::to_string(threshold) + "%") << std::endl;
        }

        std::cout << std::endl;
    }
}

void proposal(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("View Governance Proposal Details") << std::endl << std::endl;

    /* Get proposal ID */
    std::cout << InformationMsg("Enter proposal ID: ");
    std::string proposalIdStr;
    std::getline(std::cin, proposalIdStr);

    if (proposalIdStr.empty() || proposalIdStr == "exit" || proposalIdStr == "cancel")
    {
        std::cout << WarningMsg("Cancelling.") << std::endl;
        return;
    }

    uint64_t proposalId = 0;
    try
    {
        proposalId = std::stoull(proposalIdStr);
    }
    catch (...)
    {
        std::cout << WarningMsg("Invalid proposal ID!") << std::endl;
        return;
    }

    /* Get proposal */
    const auto [error, proposal] = walletBackend->getGovernanceProposal(proposalId);

    if (error != SUCCESS)
    {
        std::cout << WarningMsg("Failed to get proposal: ") << error << std::endl;
        return;
    }

    if (proposal.proposalId == 0)
    {
        std::cout << WarningMsg("Proposal not found!") << std::endl;
        return;
    }

    /* Display proposal details */
    std::cout << std::endl << InformationMsg("=== Proposal Details ===") << std::endl;
    std::cout << InformationMsg("ID: ") << SuccessMsg(std::to_string(proposal.proposalId)) << std::endl;
    std::cout << InformationMsg("Title: ") << SuccessMsg(proposal.title) << std::endl;
    std::cout << std::endl << InformationMsg("Description:") << std::endl;
    std::cout << SuccessMsg(proposal.description) << std::endl;
    std::cout << std::endl << InformationMsg("Proposer: ") << SuccessMsg(proposal.proposerAddress) << std::endl;
    std::cout << InformationMsg("Created: Block ") << SuccessMsg(std::to_string(proposal.creationHeight)) << std::endl;
    std::cout << InformationMsg("Expires: Block ") << SuccessMsg(std::to_string(proposal.expirationHeight)) << std::endl;

    std::string typeStr = "Parameter";
    if (proposal.proposalType == 1)
        typeStr = "Protocol Upgrade";
    else if (proposal.proposalType == 2)
        typeStr = "Treasury";

    std::cout << InformationMsg("Type: ") << SuccessMsg(typeStr) << std::endl;
    std::cout << InformationMsg("Status: ") << SuccessMsg(proposal.result) << std::endl;

    std::cout << std::endl << InformationMsg("Votes:") << std::endl;
    std::cout << InformationMsg("  For: ") << SuccessMsg(Utilities::formatAmount(proposal.votesFor)) << std::endl;
    std::cout << InformationMsg("  Against: ") << SuccessMsg(Utilities::formatAmount(proposal.votesAgainst)) << std::endl;
    std::cout << InformationMsg("  Total Power: ") << SuccessMsg(Utilities::formatAmount(proposal.totalVotingPower)) << std::endl;

    uint8_t threshold = 51;
    if (proposal.proposalType == 1)
        threshold = 67;
    else if (proposal.proposalType == 2)
        threshold = 51;

    uint64_t requiredVotes = (proposal.totalVotingPower * threshold) / 100;
    uint64_t percentFor = proposal.totalVotingPower > 0 ? (proposal.votesFor * 100) / proposal.totalVotingPower : 0;

    std::cout << std::endl << InformationMsg("Threshold: ") << SuccessMsg(std::to_string(threshold) + "%") << std::endl;
    std::cout << InformationMsg("Required: ") << SuccessMsg(Utilities::formatAmount(requiredVotes)) << std::endl;
    std::cout << InformationMsg("Current: ") << SuccessMsg(std::to_string(percentFor) + "%") << std::endl;

    /* Get votes for this proposal */
    const auto [votesError, votes] = walletBackend->getGovernanceProposalVotes(proposalId);

    if (votesError == SUCCESS && !votes.empty())
    {
        std::cout << std::endl << InformationMsg("Recent Votes:") << std::endl;
        size_t count = std::min(size_t(5), votes.size());
        for (size_t i = votes.size() - count; i < votes.size(); i++)
        {
            std::string voteStr = "Against";
            if (votes[i].vote == 1)
                voteStr = "For";
            else if (votes[i].vote == 2)
                voteStr = "Abstain";

            std::cout << "  " << votes[i].voterAddress.substr(0, 10) << "...";
            std::cout << " " << SuccessMsg(voteStr);
            std::cout << " (" << Utilities::formatAmount(votes[i].stakeWeight) << " votes)" << std::endl;
        }
    }
}

void castVote(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Cast a vote on a governance proposal") << std::endl << std::endl;

    /* Get proposal ID */
    std::cout << InformationMsg("Enter proposal ID: ");
    std::string proposalIdStr;
    std::getline(std::cin, proposalIdStr);

    if (proposalIdStr.empty() || proposalIdStr == "exit" || proposalIdStr == "cancel")
    {
        std::cout << WarningMsg("Cancelling.") << std::endl;
        return;
    }

    uint64_t proposalId = 0;
    try
    {
        proposalId = std::stoull(proposalIdStr);
    }
    catch (...)
    {
        std::cout << WarningMsg("Invalid proposal ID!") << std::endl;
        return;
    }

    /* Get vote */
    std::cout << std::endl << InformationMsg("Enter your vote:") << std::endl;
    std::cout << "  0 - Against" << std::endl;
    std::cout << "  1 - For" << std::endl;
    std::cout << "  2 - Abstain" << std::endl;
    std::cout << std::endl << InformationMsg("Vote (0/1/2): ");

    std::string voteStr;
    std::getline(std::cin, voteStr);

    uint8_t vote = 0;
    if (voteStr == "0")
    {
        vote = 0;
    }
    else if (voteStr == "1")
    {
        vote = 1;
    }
    else if (voteStr == "2")
    {
        vote = 2;
    }
    else
    {
        std::cout << WarningMsg("Invalid vote!") << std::endl;
        return;
    }

    /* Get voting power */
    const auto [error, votingPower, stakes] = walletBackend->getVotingPower();

    if (error == SUCCESS)
    {
        std::string voteStr2 = "Against";
        if (vote == 1)
            voteStr2 = "For";
        else if (vote == 2)
            voteStr2 = "Abstain";

        std::cout << std::endl << InformationMsg("Your voting power: ") << SuccessMsg(Utilities::formatAmount(votingPower)) << std::endl;
        std::cout << InformationMsg("Your vote: ") << SuccessMsg(voteStr2) << std::endl;
        std::cout << std::endl << WarningMsg("Confirm vote? (y/n): ");

        std::string confirm;
        std::getline(std::cin, confirm);
        Utilities::trim(confirm);

        if (confirm != "y" && confirm != "Y")
        {
            std::cout << WarningMsg("Vote cancelled.") << std::endl;
            return;
        }
    }

    /* Cast vote */
    std::cout << std::endl << InformationMsg("Casting vote...") << std::endl;

    const auto [voteError, message] = walletBackend->castVote(proposalId, vote);

    if (voteError != SUCCESS)
    {
        std::cout << WarningMsg("Failed to cast vote: ") << voteError << std::endl;
        return;
    }

    std::cout << SuccessMsg("Vote cast successfully!") << std::endl;
    std::cout << InformationMsg("Message: ") << SuccessMsg(message) << std::endl;
}

void votingPower(const std::shared_ptr<WalletBackend> walletBackend)
{
    std::cout << InformationMsg("Your Voting Power") << std::endl << std::endl;

    const auto [error, votingPower, stakes] = walletBackend->getVotingPower();

    if (error != SUCCESS)
    {
        std::cout << WarningMsg("Failed to get voting power: ") << error << std::endl;
        return;
    }

    std::cout << InformationMsg("Total Voting Power: ") << SuccessMsg(Utilities::formatAmount(votingPower) + " votes") << std::endl;

    if (stakes.empty())
    {
        std::cout << std::endl << InformationMsg("No active stakes found.") << std::endl;
        std::cout << InformationMsg("You need to stake tokens to have voting power.") << std::endl;
        return;
    }

    std::cout << std::endl << InformationMsg("Active Stakes:") << std::endl;

    for (const auto &stake : stakes)
    {
        uint64_t multiplier = 1;
        if (stake.lockDurationDays >= 360)
            multiplier = 4;
        else if (stake.lockDurationDays >= 180)
            multiplier = 3;
        else if (stake.lockDurationDays >= 90)
            multiplier = 2;

        uint64_t stakeVotingPower = stake.amount * multiplier;

        std::cout << "  " << SuccessMsg(Utilities::formatAmount(stake.amount));
        std::cout << " (" << std::to_string(stake.lockDurationDays) << " days, ";
        std::cout << std::to_string(multiplier) << "x multiplier)" << std::endl;
        std::cout << "    Voting Power: " << SuccessMsg(Utilities::formatAmount(stakeVotingPower) + " votes") << std::endl;
        std::cout << std::endl;
    }

    std::cout << InformationMsg("Voting Power Formula: Amount × Lock Multiplier") << std::endl;
    std::cout << InformationMsg("Lock Multipliers: 30 days (1x), 90 days (2x), 180 days (3x), 360 days (4x)") << std::endl;
}
