// Copyright (c) 2018, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information
#include <config/PastellaConfig.h>
#include <config/WalletConfig.h>

#pragma once

const std::string asciiArt =
"\n"
"\n"
"    ooooooooooooooooooooooooo           \n"
"   ooooooooooooooooooooooooooooo        \n"
"   ooooooooooooooooooooooooooooooo      \n"
"    ooooooooooooooooooooooooooooooo     \n"
"                         ooooooooooo    \n"
"                            ooooooooo   \n"
"           ooooooooooooo     oooooooo   \n"
"       ooooooooooooooooooo    oooooooo  \n"
"    oooooooooooooooooooooo    ooooooo   \n"
"   oooooooooooooooooooo      oooooooo   \n"
"   ooooooooo               oooooooooo   \n"
"   oooooooo      ooooooooooooooooooo    \n"
"   ooooooo    oooooooooooooooooooo      \n"
"   ooooooo    ooooooooooooooooo         \n"
"   ooooooo     oooooooooooooo           \n"
"   ooooooo                              \n"
"   ooooooo                              \n"
"   ooooooo                              \n"
"   ooooooo                              \n"
"    ooooo                               \n";

const std::string asciiArtStart =
"\n"
"\n"
"    ooooooooooooooooooooooooo           \n"
"   ooooooooooooooooooooooooooooo        \n"
"   ooooooooooooooooooooooooooooooo        Block Time: " + std::to_string(Pastella::parameters::DIFFICULTY_TARGET) + " seconds   \n"
"    ooooooooooooooooooooooooooooooo       Maximum Supply: 80,000,000 " + std::string(WalletConfig::ticker) + "\n" 
"                         ooooooooooo      P2P Port: " + std::to_string(Pastella::P2P_DEFAULT_PORT) + "\n"
"                            ooooooooo     RPC Port: " + std::to_string(Pastella::RPC_DEFAULT_PORT) + "\n"
"           ooooooooooooo     oooooooo     Wallet Port: " + std::to_string(Pastella::SERVICE_DEFAULT_PORT) + "\n"
"       ooooooooooooooooooo    oooooooo    Ticker: " + WalletConfig::ticker + "\n"
"    oooooooooooooooooooooo    ooooooo     Decimals: " + std::to_string(Pastella::parameters::PASTELLA_DISPLAY_DECIMAL_POINT) + "\n"
"   oooooooooooooooooooo      oooooooo   \n"
"   ooooooooo               oooooooooo     Website: https://pastella.org\n"
"   oooooooo      ooooooooooooooooooo      Discord: " + WalletConfig::contactLink + "\n"
"   ooooooo    oooooooooooooooooooo      \n"
"   ooooooo    ooooooooooooooooo         \n"
"   ooooooo     oooooooooooooo           \n"
"   ooooooo                              \n"
"   ooooooo                              \n"
"   ooooooo                              \n"
"   ooooooo                              \n"
"    ooooo                              \n";