// Copyright (c) 2018, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

////////////////////////////////
#include <utilities/Addresses.h>
////////////////////////////////

#include <common/Base58.h>
#include <config/PastellaConfig.h>
#include <errors/ValidateParameters.h>
#include <serialization/SerializationTools.h>

namespace Utilities
{
    /* Will throw an exception if the addresses are invalid. Please check they
       are valid before calling this function. (e.g. use validateAddresses)

       Note: Integrated addresses are not supported in the transparent system. */
    std::vector<Crypto::PublicKey> addressesToPublicKeys(const std::vector<std::string> addresses)
    {
        std::vector<Crypto::PublicKey> publicKeys;

        for (const auto &address : addresses)
        {
            publicKeys.push_back(addressToPublicKey(address));
        }

        return publicKeys;
    }

    Crypto::PublicKey addressToPublicKey(const std::string address)
    {
        Pastella::AccountPublicAddress parsedAddress;

        uint64_t prefix;

        /* Failed to parse */
        if (!parseAccountAddressString(prefix, parsedAddress, address))
        {
            throw std::invalid_argument("Address is not valid!");
        }

        /* Incorrect prefix */
        if (prefix != Pastella::parameters::PASTELLA_PUBLIC_ADDRESS_BASE58_PREFIX)
        {
            throw std::invalid_argument("Address is not valid!");
        }

        return parsedAddress.publicKey;
    }

    std::string publicKeyToAddress(const Crypto::PublicKey publicKey)
    {
        Pastella::AccountPublicAddress address;
        address.publicKey = publicKey;

        return getAccountAddressAsStr(
            Pastella::parameters::PASTELLA_PUBLIC_ADDRESS_BASE58_PREFIX, address);
    }

    /* Generates a public address from the given private key */
    std::string privateKeyToAddress(const Crypto::SecretKey privateKey)
    {
        Crypto::PublicKey publicKey;

        Crypto::secret_key_to_public_key(privateKey, publicKey);

        Pastella::AccountPublicAddress address;
        address.publicKey = publicKey;

        return getAccountAddressAsStr(
            Pastella::parameters::PASTELLA_PUBLIC_ADDRESS_BASE58_PREFIX, address);
    }

    std::string getAccountAddressAsStr(const uint64_t prefix, const Pastella::AccountPublicAddress &adr)
    {
        std::vector<uint8_t> ba;
        toBinaryArray(adr, ba);
        return Tools::Base58::encode_addr(prefix, Common::asString(ba));
    }

    bool parseAccountAddressString(uint64_t &prefix, Pastella::AccountPublicAddress &adr, const std::string &str)
    {
        std::string data;

        return Tools::Base58::decode_addr(str, prefix, data) && fromBinaryArray(adr, Common::asBinaryArray(data))
               && Crypto::check_key(adr.publicKey);
    }

} // namespace Utilities
