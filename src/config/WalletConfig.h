// Copyright (c) 2018, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <config/PastellaConfig.h>

/* Make sure everything in here is const - or it won't compile! */
namespace WalletConfig
{
    /* The prefix your coins address starts with */
    const std::string_view addressPrefix = "PAS";

    /* Your coins 'Ticker', e.g. Monero = XMR, Bitcoin = BTC */
    const std::string ticker = "PAS";

    /* The filename to output the CSV to in save_csv */
    const std::string csvFilename = "transactions.csv";

    /* The filename to read+write the address book to - consider starting with
       a leading '.' to make it hidden under mac+linux */
    const std::string addressBookFilename = ".addressBook.json";

    /* The name of your deamon */
    const std::string daemonName = "Pastellad";

    /* The name to call this wallet */
    const std::string walletName = "Pastella-Wallet";

    /* The name of service/walletd, the programmatic rpc interface to a
       wallet */
    const std::string walletdName = "Pastella-Service";

    /* The full name of your crypto */
    const std::string coinName = std::string(Pastella::COIN_NAME);

    /* Where can your users contact you for support? E.g. discord */
    const std::string contactLink = "https://discord.gg/YKh5GjTGmU";

    /* The number of decimals your coin has */
    const uint8_t numDecimalPlaces = Pastella::parameters::PASTELLA_DISPLAY_DECIMAL_POINT;

    /* The length of a standard address for your coin */
    const uint16_t standardAddressLength = 54;

    /* The default fee value to use with transactions (in ATOMIC units!) - 500 PAS */
    const uint64_t defaultFee = Pastella::parameters::MINIMUM_FEE;

    /* The minimum fee value to allow with transactions (in ATOMIC units!)  - 500 PAS */
    const uint64_t minimumFee = Pastella::parameters::MINIMUM_FEE;

    /* The minimum amount allowed to be sent - usually 1 (in ATOMIC units!) */
    const uint64_t minimumSend = 1;

    /* Is a mixin of zero disabled on your network? */
    const bool mixinZeroDisabled = false;

    /**
     * Max size of a post body response - 10MB
     * Will decrease the amount of blocks requested from the daemon if this
     * is exceeded.
     * Note - blockStoreMemoryLimit - maxBodyResponseSize should be greater
     * than zero, or no data will get cached.
     * Further note: Currently blocks request are not decreased if this is
     * exceeded. Needs to be implemented in future?
     */
    const size_t maxBodyResponseSize = 1024 * 1024 * 10;

    /**
     * The amount of memory to use storing downloaded blocks - 50MB
     */
    const size_t blockStoreMemoryLimit = 1024 * 1024 * 50;
} // namespace WalletConfig
