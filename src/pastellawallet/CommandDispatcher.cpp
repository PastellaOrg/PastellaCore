// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

//////////////////////////////////////////
#include <pastellawallet/CommandDispatcher.h>
//////////////////////////////////////////

#include <iostream>
#include <utilities/ColouredMsg.h>
#include <utilities/Input.h>
#include <pastellawallet/AddressBook.h>
#include <pastellawallet/CommandImplementations.h>
#include <pastellawallet/Open.h>
#include <pastellawallet/Transfer.h>
#include <pastellawallet/Utilities.h>

bool handleCommand(
    const std::string command,
    const std::shared_ptr<WalletBackend> walletBackend,
    const std::shared_ptr<std::mutex> mutex)
{
    /* Aquire the lock so transactions don't get printed whilst we're handling
       a command */
    std::scoped_lock lock(*mutex);

    /* Basic commands */
    if (command == "advanced")
    {
        advanced(walletBackend);
    }
    else if (command == "address")
    {
        std::cout << SuccessMsg(walletBackend->getPrimaryAddress()) << std::endl;
    }
    else if (command == "balance")
    {
        balance(walletBackend);
    }
    else if (command == "backup")
    {
        backup(walletBackend);
    }
    else if (command == "exit")
    {
        return false;
    }
    else if (command == "help")
    {
        help(walletBackend);
    }
    else if (command == "transfer")
    {
        const bool sendAll = false;

        transfer(walletBackend, sendAll);
    }
    /* Advanced commands */
    else if (command == "ab_add")
    {
        addToAddressBook();
    }
    else if (command == "ab_delete")
    {
        deleteFromAddressBook();
    }
    else if (command == "ab_list")
    {
        listAddressBook();
    }
    else if (command == "ab_send")
    {
        sendFromAddressBook(walletBackend);
    }
    else if (command == "change_password")
    {
        changePassword(walletBackend);
    }
    else if (command == "incoming_transfers")
    {
        const bool printIncoming = true;
        const bool printOutgoing = false;

        listTransfers(printIncoming, printOutgoing, walletBackend);
    }
    else if (command == "list_transfers")
    {
        const bool printIncoming = true;
        const bool printOutgoing = true;

        listTransfers(printIncoming, printOutgoing, walletBackend);
    }
    else if (command == "outgoing_transfers")
    {
        const bool printIncoming = false;
        const bool printOutgoing = true;

        listTransfers(printIncoming, printOutgoing, walletBackend);
    }
    else if (command == "reset")
    {
        reset(walletBackend);
    }
    else if (command == "save")
    {
        save(walletBackend);
    }
    else if (command == "save_csv")
    {
        saveCSV(walletBackend);
    }
    else if (command == "send_all")
    {
        const bool sendAll = true;

        transfer(walletBackend, sendAll);
    }
    else if (command == "set_log_level")
    {
        setLogLevel();
    }
    else if (command == "status")
    {
        status(walletBackend);
    }
    else if (command == "swap_node")
    {
        swapNode(walletBackend);
    }
    /* Staking commands */
    else if (command == "stake")
    {
        stake(walletBackend);
    }
    else if (command == "list_stakes")
    {
        listStakes(walletBackend);
    }
    else if (command == "staking_info")
    {
        stakingInfo(walletBackend);
    }
    else if (command == "calculate_rewards")
    {
        calculateRewards(walletBackend);
    }
    /* Governance commands */
    else if (command == "create_proposal")
    {
        createProposal(walletBackend);
    }
    else if (command == "list_proposals")
    {
        listProposals(walletBackend);
    }
    else if (command == "proposal")
    {
        proposal(walletBackend);
    }
    else if (command == "vote")
    {
        castVote(walletBackend);
    }
    else if (command == "voting_power")
    {
        votingPower(walletBackend);
    }
    /* This should never happen */
    else
    {
        throw std::runtime_error("Command was defined but not hooked up!");
    }

    return true;
}

std::shared_ptr<WalletBackend> handleLaunchCommand(const std::string launchCommand, const ZedConfig &config)
{
    if (launchCommand == "create")
    {
        return createWallet(config);
    }
    else if (launchCommand == "open")
    {
        return openWallet(config);
    }
    else if (launchCommand == "create_vanity")
    {
        return createVanityWallet(config);
    }
    else if (launchCommand == "seed_restore")
    {
        return importWalletFromSeed(config);
    }
    else if (launchCommand == "key_restore")
    {
        return importWalletFromKeys(config);
    }
    /* This should never happen */
    else
    {
        throw std::runtime_error("Command was defined but not hooked up!");
    }
}
