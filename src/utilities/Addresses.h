// Copyright (c) 2018, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <Pastella.h>
#include <errors/Errors.h>
#include <string>
#include <vector>

namespace Utilities
{
    std::vector<Crypto::PublicKey> addressesToPublicKeys(const std::vector<std::string> addresses);
    Crypto::PublicKey addressToPublicKey(const std::string address);
    std::string publicKeyToAddress(const Crypto::PublicKey publicKey);

    std::string privateKeyToAddress(const Crypto::SecretKey privateKey);

    std::string getAccountAddressAsStr(const uint64_t prefix, const Pastella::AccountPublicAddress &adr);

    bool parseAccountAddressString(uint64_t &prefix, Pastella::AccountPublicAddress &adr, const std::string &str);
} // namespace Utilities
