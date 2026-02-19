// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <CryptoTypes.h>

/* Forward declarations */
class WalletBackend;
struct ZedConfig;

struct VanityResult
{
    bool found;
    Crypto::PublicKey publicKey;
    Crypto::SecretKey secretKey;
    std::string address;
    uint64_t attempts;
};

std::shared_ptr<WalletBackend> createVanityWallet(const ZedConfig &config);

bool isValidBase58(const std::string &str);

bool hasAmbiguousChars(const std::string &str);

std::string checkPattern(const std::string &pattern);
