// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

//////////////////////////////////////
#include <errors/ValidateParameters.h>
//////////////////////////////////////

#include <common/Base58.h>
#include <config/PastellaConfig.h>
#include <config/WalletConfig.h>

extern "C"
{
#include <crypto/crypto-ops.h>
}

#include <common/PastellaTools.h>
#include <common/TransactionExtra.h>
#include <regex>
#include <utilities/Addresses.h>
#include <utilities/Utilities.h>

Error validateTransaction(
    const std::vector<std::pair<std::string, uint64_t>> destinations,
    const WalletTypes::FeeType fee,
    const std::vector<std::string> subWalletsToTakeFrom,
    const std::string changeAddress,
    const std::shared_ptr<SubWallets> subWallets,
    const uint64_t currentHeight)
{
    /* Validate the destinations */
    if (Error error = validateDestinations(destinations); error != SUCCESS)
    {
        return error;
    }

    /* Verify the subwallets to take from exist */
    if (Error error = validateOurAddresses(subWalletsToTakeFrom, subWallets); error != SUCCESS)
    {
        return error;
    }

    /* Validate we have enough money for the transaction */
    if (Error error = validateAmount(destinations, fee, subWalletsToTakeFrom, subWallets, currentHeight);
        error != SUCCESS)
    {
        return error;
    }

    /* Verify the change address is valid and exists in the subwallets */
    if (Error error = validateOurAddresses({changeAddress}, subWallets); error != SUCCESS)
    {
        return error;
    }

    return SUCCESS;
}

Error validateHash(const std::string hash)
{
    if (hash.length() != 64)
    {
        return HASH_WRONG_LENGTH;
    }

    std::regex hexRegex("[a-zA-Z0-9]{64}");

    if (!std::regex_match(hash, hexRegex))
    {
        return HASH_INVALID;
    }

    return SUCCESS;
}

Error validatePrivateKey(const Crypto::SecretKey &privateKey)
{
    const bool valid = sc_check(reinterpret_cast<const unsigned char *>(&privateKey)) == 0;

    if (valid)
    {
        return SUCCESS;
    }
    else
    {
        return INVALID_PRIVATE_KEY;
    }
}

Error validatePublicKey(const Crypto::PublicKey &publicKey)
{
    const bool valid = Crypto::check_key(publicKey);

    if (valid)
    {
        return SUCCESS;
    }
    else
    {
        return INVALID_PUBLIC_KEY;
    }
}

Error validateMixin(const uint64_t mixin, const uint64_t height)
{
    /* Mixin validation disabled - transparent system does not use mixins */
    /* In the new transparent system, this parameter is ignored */
    (void)mixin;
    (void)height;
    return SUCCESS;
}

Error validateAmount(
    const std::vector<std::pair<std::string, uint64_t>> destinations,
    const WalletTypes::FeeType fee,
    const std::vector<std::string> subWalletsToTakeFrom,
    const std::shared_ptr<SubWallets> subWallets,
    const uint64_t currentHeight)
{
    if (!fee.isFeePerByte && !fee.isFixedFee && !fee.isMinimumFee)
    {
        throw std::runtime_error("Programmer error: fee type not specified");
    }

    /* Using a fee per byte, and doesn't meet the min fee per byte requirement. */
    if (fee.isFeePerByte && fee.feePerByte < Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1)
    {
        return FEE_TOO_SMALL;
    }

    /* Get the available balance, using the source addresses */
    const auto [availableBalance, lockedBalance] = subWallets->getBalance(
        Utilities::addressesToPublicKeys(subWalletsToTakeFrom),
        /* Take from all if no subwallets specified */
        subWalletsToTakeFrom.empty(),
        currentHeight);

    /* Get the total amount of the transaction */
    uint64_t totalAmount = Utilities::getTransactionSum(destinations);

    std::vector<uint64_t> amounts;

    /* If we are using a fixed fee, we can calculate if we've got enough funds
     * to cover the transaction. If we don't, we'll leave the verification until
     * we have constructed the transaction */
    if (fee.isFixedFee)
    {
        totalAmount += fee.fixedFee;
        amounts.push_back(fee.fixedFee);
    }

    std::transform(destinations.begin(), destinations.end(), std::back_inserter(amounts), [](const auto destination) {
        return destination.second;
    });

    /* Check the total amount we're sending is not >= uint64_t */
    if (Utilities::sumWillOverflow(amounts))
    {
        return WILL_OVERFLOW;
    }

    if (totalAmount > availableBalance)
    {
        return NOT_ENOUGH_BALANCE;
    }

    return SUCCESS;
}

Error validateDestinations(const std::vector<std::pair<std::string, uint64_t>> destinations)
{
    /* Make sure there is at least one destination */
    if (destinations.empty())
    {
        return NO_DESTINATIONS_GIVEN;
    }

    std::vector<std::string> destinationAddresses;

    for (const auto &[destination, amount] : destinations)
    {
        /* Check all of the amounts are > 0 */
        if (amount == 0)
        {
            return AMOUNT_IS_ZERO;
        }

        destinationAddresses.push_back(destination);
    }

    /* Validate the addresses are good [Integrated addresses allowed] */
    if (Error error = validateAddresses(destinationAddresses, true); error != SUCCESS)
    {
        return error;
    }

    return SUCCESS;
}

Error validateAddresses(std::vector<std::string> addresses, const bool integratedAddressesAllowed)
{
    for (auto &address : addresses)
    {
        /* Address is the wrong length - only standard addresses supported now */
        if (address.length() != WalletConfig::standardAddressLength)
        {
            std::stringstream stream;

            stream << "The address should be " << WalletConfig::standardAddressLength
                   << " characters, but it is " << address.length() << " characters. "
                   << "Integrated addresses are not supported in transparent mode.";

            return Error(ADDRESS_WRONG_LENGTH, stream.str());
        }

        /* Address has the wrong prefix */
        if (address.substr(0, WalletConfig::addressPrefix.length()) != WalletConfig::addressPrefix)
        {
            return ADDRESS_WRONG_PREFIX;
        }

        /* Not used */
        uint64_t ignore;

        /* Not used */
        Pastella::AccountPublicAddress ignore2;

        if (!Utilities::parseAccountAddressString(ignore, ignore2, address))
        {
            return ADDRESS_NOT_VALID;
        }
    }

    return SUCCESS;
}

Error validateOurAddresses(const std::vector<std::string> addresses, const std::shared_ptr<SubWallets> subWallets)
{
    /* Validate the addresses are valid [Integrated addresses not allowed] */
    if (Error error = validateAddresses(addresses, false); error != SUCCESS)
    {
        return error;
    }

    for (const auto address : addresses)
    {
        const auto publicKey = Utilities::addressToPublicKey(address);

        const auto &keys = subWallets->m_publicKeys;

        if (std::find(keys.begin(), keys.end(), publicKey) == keys.end())
        {
            return Error(
                ADDRESS_NOT_IN_WALLET,
                "The address given (" + address + ") does not exist in the wallet container, but it is "
                    + "required to exist for this operation.");
        }
    }

    return SUCCESS;
}
