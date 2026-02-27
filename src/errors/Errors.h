// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <string>

/* Note: Putting the number of the error is not needed, as they auto increment,
   however, it makes it easier to see at a glance what error you got, whilst
   developing */
enum ErrorCode
{
    /* No error, operation succeeded. */
    SUCCESS = 0,

    /* The wallet filename given does not exist or the program does not have
       permission to view it */
    FILENAME_NON_EXISTENT = 1,

    /* The output filename was unable to be opened for saving, probably due
       to invalid characters */
    INVALID_WALLET_FILENAME = 2,

    /* The wallet does not have the wallet identifier prefix */
    NOT_A_WALLET_FILE = 3,

    /* The file has the correct wallet file prefix, but is corrupted in some
       other way, such as a missing IV */
    WALLET_FILE_CORRUPTED = 4,

    /* Either the AES decryption failed due to wrong padding, or the decrypted
       data does not have the correct prefix indicating the password is
       correct. */
    WRONG_PASSWORD = 5,

    /* The wallet file is using a different version than the version supported
       by this version of the software. (Also could be potential corruption.) */
    UNSUPPORTED_WALLET_FILE_FORMAT_VERSION = 6,

    /* The mnemonic seed is invalid for some reason, for example, it has the
       wrong length, or an invalid checksum */
    INVALID_MNEMONIC = 7,

    /* Trying to create a wallet file which already exists */
    WALLET_FILE_ALREADY_EXISTS = 8,

    /* Operation will cause int overflow */
    WILL_OVERFLOW = 9,

    /* The address given does not exist in this container, and it's required,
       for example you specified it as the address to get the balance from */
    ADDRESS_NOT_IN_WALLET = 10,

    /* Amount + fee is greater than the total balance available in the
       subwallets specified (or all wallets, if not specified) */
    NOT_ENOUGH_BALANCE = 11,

    /* The address is the wrong length - neither a standard, nor an integrated
       address */
    ADDRESS_WRONG_LENGTH = 12,

    /* The address does not have the correct prefix, e.g. does not begin with
       TRTL (or whatever is specified in WalletConfig::addressPrefix) */
    ADDRESS_WRONG_PREFIX = 13,

    /* The address is not fully comprised of base58 characters */
    ADDRESS_NOT_BASE58 = 14,

    /* The address is invalid for some other reason (possibly checksum) */
    ADDRESS_NOT_VALID = 15,

    /* The fee given is lower than the Pastella::parameters::MINIMUM_FEE */
    FEE_TOO_SMALL = 17,

    /* The destinations array is empty */
    NO_DESTINATIONS_GIVEN = 18,

    /* One of the destination parameters has an amount given of zero. */
    AMOUNT_IS_ZERO = 19,

    /* Could not contact the daemon to complete the request. Ensure it is
       online and not frozen */
    DAEMON_OFFLINE = 30,

    /* An error occured whilst the daemon processed the request. Possibly our
       software is outdated, the daemon is faulty, or there is a programmer
       error. Check your daemon logs for more info (set_log 4) */
    DAEMON_ERROR = 31,

    /* The transction is too large (in BYTES, not AMOUNT) to fit in a block.
       Either:
       1) decrease the amount you are sending
       2) split your transaction up into multiple smaller transactions */
    TOO_MANY_INPUTS_TO_FIT_IN_BLOCK = 32,

    /* Mnemonic has a word that is not in the english word list */
    MNEMONIC_INVALID_WORD = 33,

    /* Mnemonic seed is not 25 words */
    MNEMONIC_WRONG_LENGTH = 34,

    /* The mnemonic seed has an invalid checksum word */
    MNEMONIC_INVALID_CHECKSUM = 35,

    /* Attempted to add a subwallet which already exists in the container */
    SUBWALLET_ALREADY_EXISTS = 38,

    /* Cannot perform this operation when using a view wallet */
    ILLEGAL_VIEW_WALLET_OPERATION = 39,

    /* Cannot perform this operation when using a non view wallet */
    ILLEGAL_NON_VIEW_WALLET_OPERATION = 40,

    KEYS_NOT_DETERMINISTIC = 41,

    /* The primary address cannot be deleted */
    CANNOT_DELETE_PRIMARY_ADDRESS = 42,

    /* Couldn't find the private key for this hash */
    TX_PRIVATE_KEY_NOT_FOUND = 43,

    /* Amounts not a member of PRETTY_AMOUNTS */
    AMOUNTS_NOT_PRETTY = 44,

    /* Tx fee is not the same as specified fee */
    UNEXPECTED_FEE = 45,

    /* Value given is negative, but must be >= 0
       NOTE: Not used in WalletBackend, only here to maintain API compatibility
       with turtlecoin-wallet-backend-js */
    NEGATIVE_VALUE_GIVEN = 46,

    /* Key is not 64 char hex
       NOTE: Not used in WalletBackend, only here to maintain API compatibility
       with turtlecoin-wallet-backend-js */
    INVALID_KEY_FORMAT = 47,

    /* Hash not 64 chars */
    HASH_WRONG_LENGTH = 48,

    /* Hash not hex */
    HASH_INVALID = 49,

    /* Number is a float, not an integer
       NOTE: Not used in WalletBackend, only here to maintain API compatibility
       with turtlecoin-wallet-backend-js */
    NON_INTEGER_GIVEN = 50,

    /* Not on ed25519 curve */
    INVALID_PUBLIC_KEY = 51,

    /* Not on ed25519 curve */
    INVALID_PRIVATE_KEY = 52,

    /* Extra data for transaction is not a valid hexadecimal string */
    INVALID_EXTRA_DATA = 53,

    /* An unknown error occured */
    UNKNOWN_ERROR = 54,

    /* The daemon received our request but we timed out before we could figure
     * out if it completed */
    DAEMON_STILL_PROCESSING = 55,

    /* The transaction has more outputs than are permitted for the number
     * inputs that have been provided */
    OUTPUT_DECOMPOSITION = 56,

    /* The inputs that were included in a prepared transaction have since been
     * spent or are for some other reason no longer available. */
    PREPARED_TRANSACTION_EXPIRED = 57,

    /* The prepared transaction hash specified does not exist, either because
     * it never existed, or because the wallet was restarted and the prepared
     * transaction state was lost */
    PREPARED_TRANSACTION_NOT_FOUND = 58,

    /* Staking Related Errors */

    /* Staking amount is below minimum required amount */
    STAKING_AMOUNT_TOO_LOW = 59,

    /* Staking lock duration is outside allowed range */
    INVALID_LOCK_DURATION = 60,

    /* Staking transaction hash is invalid or not found */
    INVALID_STAKING_TX_HASH = 61,

    /* Staking transaction was not found in blockchain */
    STAKING_TX_NOT_FOUND = 62,

    /* Transaction is not a staking transaction */
    NOT_A_STAKING_TRANSACTION = 63,

    /* Reward amount is invalid */
    INVALID_REWARD_AMOUNT = 65,

    /* Failed to create transaction extra data */
    FAILED_TO_CREATE_TX_EXTRA = 66,

    /* Staking outputs need to be prepared before staking */
    STAKING_OUTPUTS_PREPARATION_NEEDED = 67,

    /* Staking is not enabled at current height */
    STAKING_NOT_ENABLED = 68,

    /* Governance Related Errors */

    /* Governance is not enabled at current height */
    GOVERNANCE_NOT_ENABLED = 70,
};

class Error
{
  public:
    /* Default constructor */
    Error(): m_errorCode(SUCCESS) {};

    Error(const ErrorCode code): m_errorCode(code) {};

    /* We can use a custom message instead of our standard message, for example,
       if the message depends upon the parameters. E.g: "Mnemonic seed should
       be 25 words, but it is 23 words" */
    Error(const ErrorCode code, const std::string customMessage): m_errorCode(code), m_customMessage(customMessage) {};

    std::string getErrorMessage() const;

    ErrorCode getErrorCode() const;

    bool operator==(const ErrorCode code) const
    {
        return code == m_errorCode;
    }

    bool operator!=(const ErrorCode code) const
    {
        return !(code == m_errorCode);
    }

    /* Allows us to do stuff like:
       if (error) {}
       Returns true if the error code is not success. */
    explicit operator bool() const
    {
        return m_errorCode != SUCCESS;
    }

  private:
    /* May be empty */
    std::string m_customMessage;

    ErrorCode m_errorCode;
};

/* Overloading the << operator */
inline std::ostream &operator<<(std::ostream &os, const Error &error)
{
    os << error.getErrorMessage();
    return os;
}
