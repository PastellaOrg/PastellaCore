// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "CryptoTypes.h"
#include "rapidjson/document.h"

#include <errors/Errors.h>
#include <nigel/Nigel.h>
#include <string>
#include <subwallets/SubWallets.h>
#include <tuple>
#include <vector>
#include <walletbackend/WalletSynchronizer.h>
#include <walletbackend/WalletSynchronizerRAIIWrapper.h>

class WalletBackend
{
  public:
    /////////////////////////
    /* Public Constructors */
    /////////////////////////

    /* Very heavily suggested to not call this directly. Call one of the
       below functions to correctly initialize a wallet. This is left
       public so the json serialization works correctly. */
    WalletBackend();

    /* Deconstructor */
    ~WalletBackend();

    /* Delete the copy constructor */
    WalletBackend(const WalletBackend &) = delete;

    /* Delete the assignment operator */
    WalletBackend &operator=(const WalletBackend &) = delete;

    /* Delete the move constructor */
    WalletBackend(WalletBackend &&old) = delete;

    /* Delete the move assignment operator */
    WalletBackend &operator=(WalletBackend &&old) = delete;

    /////////////////////////////
    /* Public static functions */
    /////////////////////////////

    /* Imports a wallet from a mnemonic seed. Returns the wallet class,
       or an error. */
    static std::tuple<Error, std::shared_ptr<WalletBackend>> importWalletFromSeed(
        const std::string mnemonicSeed,
        const std::string filename,
        const std::string password,
        const uint64_t scanHeight,
        const std::string daemonHost,
        const uint16_t daemonPort,
        const bool daemonSSL,
        const unsigned int syncThreadCount = std::thread::hardware_concurrency());

    /* Imports a wallet from a private key. Returns the wallet class, or an error. */
    static std::tuple<Error, std::shared_ptr<WalletBackend>> importWalletFromKeys(
        const Crypto::SecretKey privateKey,
        const std::string filename,
        const std::string password,
        const uint64_t scanHeight,
        const std::string daemonHost,
        const uint16_t daemonPort,
        const bool daemonSSL,
        const unsigned int syncThreadCount = std::thread::hardware_concurrency());

    /* Creates a new wallet with the given filename and password */
    static std::tuple<Error, std::shared_ptr<WalletBackend>> createWallet(
        const std::string filename,
        const std::string password,
        const std::string daemonHost,
        const uint16_t daemonPort,
        const bool daemonSSL,
        const unsigned int syncThreadCount = std::thread::hardware_concurrency());

    /* Opens a wallet already on disk with the given filename + password */
    static std::tuple<Error, std::shared_ptr<WalletBackend>> openWallet(
        const std::string filename,
        const std::string password,
        const std::string daemonHost,
        const uint16_t daemonPort,
        const bool daemonSSL,
        const unsigned int syncThreadCount = std::thread::hardware_concurrency());

    static Error saveWalletJSONToDisk(std::string walletJSON, std::string filename, std::string password);

    /////////////////////////////
    /* Public member functions */
    /////////////////////////////

    /* Save the wallet to disk */
    Error save() const;

    /* Converts the class to a json string */
    std::string toJSON() const;

    /* Initializes the class from a json string */
    Error fromJSON(const rapidjson::Document &j);

    /* Initializes the class from a json string, and inits the stuff we
       can't init from the json */
    Error fromJSON(
        const rapidjson::Document &j,
        const std::string filename,
        const std::string password,
        const std::string daemonHost,
        const uint16_t daemonPort,
        const bool daemonSSL,
        const unsigned int syncThreadCount);

    /* Remove a previously prepared transaction. */
    bool removePreparedTransaction(const Crypto::Hash &transactionHash);

    /* Sends a previously prepared transaction to the network */
    std::tuple<Error, Crypto::Hash> sendPreparedTransaction(
        const Crypto::Hash transactionHash);

    /* Send a transaction of amount to destination */
    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendTransactionBasic(
        const std::string destination,
        const uint64_t amount,
        const bool sendAll = false,
        const bool sendTransaction = true);

    /* Advanced send transaction, specify change address, etc */
    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendTransactionAdvanced(
        const std::vector<std::pair<std::string, uint64_t>> destinations,
        const WalletTypes::FeeType fee,
        const std::vector<std::string> subWalletsToTakeFrom,
        const std::string changeAddress,
        const uint64_t unlockTime,
        const std::vector<uint8_t> extraData,
        const bool sendAll = false,
        const bool sendTransaction = true);

    /********************/
    /* Staking Operations */
    /********************/

    /* Send a staking transaction to lock funds for rewards */
    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo, std::string> stake(
        const uint64_t amount,
        const uint32_t lockDurationDays,
        const std::string address = "",
        const bool sendTransaction = true);

    /* Get the balance for one subwallet (error, unlocked, locked) */
    std::tuple<Error, uint64_t, uint64_t> getBalance(const std::string address) const;

    /* Get the balance for all subwallets */
    std::tuple<uint64_t, uint64_t> getTotalBalance() const;

    uint64_t getTotalUnlockedBalance() const;

    /* Make a new sub wallet (gens a deterministic privateKey) */
    std::tuple<Error, std::string, Crypto::SecretKey, uint64_t> addSubWallet();

    /* Import a sub wallet with the given privateKey */
    std::tuple<Error, std::string> importSubWallet(const Crypto::SecretKey privateKey, const uint64_t scanHeight);

    /* Import a deterministic sub wallet using the given wallet index */
    std::tuple<Error, std::string> importSubWallet(const uint64_t walletIndex, const uint64_t scanHeight);

    /* Import a view only sub wallet with the given publicKey */
    std::tuple<Error, std::string>
        importViewSubWallet(const Crypto::PublicKey publicKey, const uint64_t scanHeight);

    Error deleteSubWallet(const std::string address);

    /* Scan the blockchain, starting from scanHeight / timestamp */
    void reset(uint64_t scanHeight, uint64_t timestamp);

    /* Get the filename of the wallet on disk */
    std::string getWalletLocation() const;

    /* Get the primary address */
    std::string getPrimaryAddress() const;

    /* Get a list of all addresses in the wallet */
    std::vector<std::string> getAddresses() const;

    uint64_t getWalletCount() const;

    /* wallet sync height, local blockchain sync height,
       remote blockchain sync height */
    std::tuple<uint64_t, uint64_t, uint64_t> getSyncStatus() const;

    /* Get the wallet password */
    std::string getWalletPassword() const;

    /* Change the wallet password and save the wallet with the new password */
    Error changePassword(const std::string newPassword);

    std::tuple<Error, Crypto::PublicKey, Crypto::SecretKey, uint64_t> getKeys(const std::string &address) const;

    /* Get the private key for the primary address */
    Crypto::SecretKey getPrimaryAddressPrivateKey() const;

    /* Get the primary address mnemonic seed, if possible */
    std::tuple<Error, std::string> getMnemonicSeed() const;

    /* Gets the mnemonic seed for the given address, if possible */
    std::tuple<Error, std::string> getMnemonicSeedForAddress(const std::string &address) const;

    /* Get all transactions */
    std::vector<WalletTypes::Transaction> getTransactions() const;

    /* Get all unconfirmed (outgoing, sent) transactions */
    std::vector<WalletTypes::Transaction> getUnconfirmedTransactions() const;

    /* Get sync heights, hashrate, peer count */
    WalletTypes::WalletStatus getStatus() const;

    /* Returns transactions in the range [startHeight, endHeight - 1] - so if
       we give 1, 100, it will return transactions from block 1 to block 99 */
    std::vector<WalletTypes::Transaction>
        getTransactionsRange(const uint64_t startHeight, const uint64_t endHeight) const;

    /* Get the node fee and address ({0, ""} if empty) */
    std::tuple<uint64_t, std::string> getNodeFee() const;

    /* Returns the node host and port */
    std::tuple<std::string, uint16_t, bool> getNodeAddress() const;

    /* Swap to a different daemon node */
    void swapNode(std::string daemonHost, uint16_t daemonPort, bool daemonSSL);

    /* Whether we have recieved info from the daemon at some point */
    bool daemonOnline() const;

    /* Get access to the daemon instance */
    std::shared_ptr<Nigel> getDaemon() const;

    std::tuple<Error, std::string> getAddress(const Crypto::PublicKey publicKey) const;

    std::tuple<Error, Crypto::SecretKey> getTxPrivateKey(const Crypto::Hash txHash) const;

    std::vector<std::tuple<std::string, uint64_t, uint64_t>> getBalances() const;

    /********************/
    /* Staking Queries */
    /********************/

    /* Get all active stakes for this wallet */
    std::vector<WalletTypes::StakeInfo> getUserStakes() const;
    std::vector<WalletTypes::StakeInfo> getUserStakesByHashes(const std::vector<std::string> &stakingHashes) const;

    /* Get pending rewards for all stakes */
    uint64_t getPendingRewards() const;

    /* Get total amount currently staked */
    uint64_t getTotalStaked() const;

    /* Check if wallet has any active stakes */
    bool hasActiveStake() const;

    /* Governance Operations */
    /***********************/

    /* Create a governance proposal */
    std::tuple<Error, std::string> createProposal(
        const std::string title,
        const std::string description,
        const uint8_t proposalType,
        const uint64_t amount = 0,
        const std::string recipientAddress = "");

    /* Cast a vote on a governance proposal */
    std::tuple<Error, std::string> castVote(
        const uint64_t proposalId,
        const uint8_t vote);

    /* Governance Queries */
    /*********************/

    /* Get all governance proposals */
    std::tuple<Error, std::vector<WalletTypes::GovernanceProposal>> getGovernanceProposals(
        const bool activeOnly = false) const;

    /* Get specific governance proposal */
    std::tuple<Error, WalletTypes::GovernanceProposal> getGovernanceProposal(
        const uint64_t proposalId) const;

    /* Get votes for a proposal */
    std::tuple<Error, std::vector<WalletTypes::GovernanceVote>> getGovernanceProposalVotes(
        const uint64_t proposalId) const;

    /* Get wallet's current voting power */
    std::tuple<Error, uint64_t, std::vector<WalletTypes::StakeInfo>> getVotingPower() const;

    static bool tryUpgradeWalletFormat(
        const std::string filename,
        const std::string password,
        const std::string daemonHost,
        const uint16_t daemonPort);

    /////////////////////////////
    /* Public member variables */
    /////////////////////////////

    std::shared_ptr<EventHandler> m_eventHandler;

  private:
    //////////////////////////
    /* Private constructors */
    //////////////////////////

    /* Standard Constructor */
    WalletBackend(
        const std::string filename,
        const std::string password,
        const Crypto::SecretKey privateKey,
        const uint64_t scanHeight,
        const bool newWallet,
        const std::string daemonHost,
        const uint16_t daemonPort,
        const bool daemonSSL,
        const unsigned int syncThreadCount);

    /* VIEW WALLET CONSTRUCTOR REMOVED: No longer needed in transparent system */

    //////////////////////////////
    /* Private member functions */
    //////////////////////////////

    Error unsafeSave() const;

    void init();


    //////////////////////////////
    /* Private member variables */
    //////////////////////////////

    /* The filename the wallet is saved to */
    std::string m_filename;

    /* The password the wallet is encrypted with */
    std::string m_password;

    /* The sub wallets container (Using a shared_ptr here so
       the WalletSynchronizer has access to it) */
    std::shared_ptr<SubWallets> m_subWallets;

    /* The daemon connection */
    std::shared_ptr<Nigel> m_daemon = nullptr;

    std::shared_ptr<WalletSynchronizer> m_walletSynchronizer;

    std::shared_ptr<WalletSynchronizerRAIIWrapper> m_syncRAIIWrapper;

    unsigned int m_syncThreadCount;

    /* Prepared, unsent transactions. */
    std::unordered_map<Crypto::Hash, WalletTypes::PreparedTransactionInfo> m_preparedTransactions;

    /* Ensure we only send one transaction in parallel, otherwise txs will likely fail. */
    std::mutex m_transactionMutex;
};