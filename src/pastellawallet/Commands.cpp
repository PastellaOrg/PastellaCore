// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

/////////////////////////////////
#include <pastellawallet/Commands.h>
/////////////////////////////////

#include <config/WalletConfig.h>
#include <utilities/Container.h>

std::vector<Command> startupCommands()
{
    return {
        Command("open", "Open a wallet already on your system"),
        Command("create", "Create a new wallet"),
        Command("create_vanity", "Create a vanity wallet with custom address"),
        Command("seed_restore", "Restore a wallet using a seed phrase of words"),
        Command("key_restore", "Restore a wallet using your private key"),
        Command("exit", "Exit the program"),
    };
}

std::vector<Command> nodeDownCommands()
{
    return {
        Command("try_again", "Try to connect to the node again"),
        Command("continue", "Continue to the wallet interface regardless"),
        Command("swap_node", "Specify a new daemon address/port to connect to"),
        Command("exit", "Exit the program"),
    };
}

std::vector<AdvancedCommand> allCommands()
{
    return {
        /* Basic commands */
        AdvancedCommand("advanced", "List available advanced commands", false),
        AdvancedCommand("address", "Display your payment address", false),
        AdvancedCommand("balance", "Display how much " + WalletConfig::ticker + " you have", false),
        AdvancedCommand("backup", "Backup your private keys and/or seed", false),
        AdvancedCommand("exit", "Exit and save your wallet", false),
        AdvancedCommand("help", "List this help message", false),
        AdvancedCommand("transfer", "Send " + WalletConfig::ticker + " to someone", false),

        /* Advanced commands */
        AdvancedCommand("ab_add", "Add a person to your address book", true),
        AdvancedCommand("ab_delete", "Delete a person in your address book", true),
        AdvancedCommand("ab_list", "List everyone in your address book", true),
        AdvancedCommand("ab_send", "Send " + WalletConfig::ticker + " to someone in your address book", true),
        AdvancedCommand("change_password", "Change your wallet password", true),
        AdvancedCommand("incoming_transfers", "Show incoming transfers", true),
        AdvancedCommand("list_transfers", "Show all transfers", true),
        AdvancedCommand("outgoing_transfers", "Show outgoing transfers", true),
        AdvancedCommand("reset", "Recheck the chain from zero for transactions", true),
        AdvancedCommand("save", "Save your wallet state", true),
        AdvancedCommand("save_csv", "Save all wallet transactions to a CSV file", true),
        AdvancedCommand("send_all", "Send all your balance to someone", true),
        AdvancedCommand("set_log_level", "Alter the logging level", true),
        AdvancedCommand("status", "Display sync status and network hashrate", true),
        AdvancedCommand("swap_node", "Specify a new daemon address/port to sync from", true),
        AdvancedCommand("stake", std::string("Stake ") + std::string(WalletConfig::ticker) + " tokens for a specified period", true),
        AdvancedCommand("list_stakes", "List all your active staking positions", true),
        AdvancedCommand("staking_info", "Display staking system information", true),
        AdvancedCommand("calculate_rewards", "Calculate potential staking rewards", true),

        /* Governance commands */
        AdvancedCommand("create_proposal", "Create a new governance proposal", true),
        AdvancedCommand("list_proposals", "List all governance proposals", true),
        AdvancedCommand("proposal", "View governance proposal details", true),
        AdvancedCommand("vote", "Cast a vote on a governance proposal", true),
        AdvancedCommand("voting_power", "Check your current voting power", true),
    };
}

std::vector<AdvancedCommand> basicCommands()
{
    return Utilities::filter(allCommands(), [](AdvancedCommand c) { return !c.advanced; });
}

std::vector<AdvancedCommand> advancedCommands()
{
    return Utilities::filter(allCommands(), [](AdvancedCommand c) { return c.advanced; });
}
