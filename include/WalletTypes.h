// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "rapidjson/document.h"
#include "rapidjson/writer.h"

#include <Pastella.h>
#include <errors/Errors.h>
#include <JsonHelper.h>
#include <optional>
#include <string>
#include <unordered_map>

namespace WalletTypes
{
    struct KeyOutput
    {
        Crypto::PublicKey key;
        uint64_t amount;
        /* Daemon doesn't supply this, blockchain cache api does. */
        std::optional<uint64_t> globalOutputIndex;
    };

    /* A coinbase transaction (i.e., a miner reward, there is one of these in
       every block). Coinbase transactions have no inputs. We call this a raw
       transaction, because it is simply key images and amounts */
    struct RawCoinbaseTransaction
    {
        /* The outputs of the transaction, amounts and keys */
        std::vector<KeyOutput> keyOutputs;

        /* The hash of the transaction */
        Crypto::Hash hash;

        /* The public key of this transaction, taken from the tx extra */
        Crypto::PublicKey transactionPublicKey;

        /* When this transaction's inputs become spendable. Some genius thought
           it was a good idea to use this field as both a block height, and a
           unix timestamp. If the value is greater than
           PASTELLA_MAX_BLOCK_NUMBER (In PastellaConfig) it is treated
           as a unix timestamp, else it is treated as a block height. */
        uint64_t unlockTime;

        size_t memoryUsage() const
        {
            return keyOutputs.size() * sizeof(KeyOutput) + sizeof(keyOutputs) + sizeof(hash)
                   + sizeof(transactionPublicKey) + sizeof(unlockTime);
        }
    };

    /* A raw transaction, simply key images and amounts */
    struct RawTransaction : RawCoinbaseTransaction
    {
        /* The raw transaction extra data - contains staking information */
        std::vector<uint8_t> extra;

        /* The inputs used for a transaction, can be used to track outgoing
           transactions */
        std::vector<Pastella::KeyInput> keyInputs;

        size_t memoryUsage() const
        {
            return 0
                   + extra.size() * sizeof(uint8_t) + sizeof(extra)
                   + keyInputs.size() * sizeof(Pastella::KeyInput)
                   + sizeof(keyInputs) + RawCoinbaseTransaction::memoryUsage();
        }
    };

    /* A 'block' with the very basics needed to sync the transactions */
    struct WalletBlockInfo
    {
        /* The coinbase transaction. Optional, since we can skip fetching
           coinbase transactions from daemon. */
        std::optional<RawCoinbaseTransaction> coinbaseTransaction;

        /* The transactions in the block */
        std::vector<RawTransaction> transactions;

        /* Staking transactions - transactions that are starting to be staked */
        std::vector<RawTransaction> stakingTransactions;

        /* The block height (duh!) */
        uint64_t blockHeight;

        /* The hash of the block */
        Crypto::Hash blockHash;

        /* The timestamp of the block */
        uint64_t blockTimestamp;

        size_t memoryUsage() const
        {
            const size_t txUsage = std::accumulate(
                transactions.begin(), transactions.end(), sizeof(transactions), [](const auto acc, const auto item) {
                    return acc + item.memoryUsage();
                });
            const size_t stakingTxUsage = std::accumulate(
                stakingTransactions.begin(), stakingTransactions.end(), sizeof(stakingTransactions), [](const auto acc, const auto item) {
                    return acc + item.memoryUsage();
                });
            return coinbaseTransaction ? coinbaseTransaction->memoryUsage()
                                       : sizeof(coinbaseTransaction) + txUsage + stakingTxUsage + sizeof(blockHeight) + sizeof(blockHash)
                                             + sizeof(blockTimestamp);
        }
    };

    struct TransactionInput
    {
        /* STEALTH ADDRESS REMOVAL: keyImage removed - was used for double-spend protection */

        /* The value of this input */
        uint64_t amount;

        /* The block height this input's transaction was included in
           (Need this for removing inputs that were received on a forked
           chain) */
        uint64_t blockHeight;

        /* The transaction public key that was included in the tx_extra of the
           transaction */
        Crypto::PublicKey transactionPublicKey;

        /* The index of this input in the transaction */
        uint64_t transactionIndex;

        /* The index of this output in the 'DB' */
        std::optional<uint64_t> globalOutputIndex;

        /* The transaction key we took from the outputs */
        Crypto::PublicKey key;

        /* If spent, what height did we spend it at. Used to remove spent
           transaction inputs once they are sure to not be removed from a
           forked chain. */
        uint64_t spendHeight;

        /* When does this input unlock for spending. Default is instantly
           unlocked, or blockHeight + PASTELLA_MINED_MONEY_UNLOCK_WINDOW
           for a coinbase/miner transaction. Users can specify a custom
           unlock height however. */
        uint64_t unlockTime;

        /* The transaction hash of the transaction that contains this input */
        Crypto::Hash parentTransactionHash;

        /* The private ephemeral generated along with the key (REMOVED in transparent system) */
        /* STEALTH ADDRESS REMOVAL: privateEphemeral removed - derived from stealth address */

        bool operator==(const TransactionInput &other)
        {
            /* Use parentTransactionHash + transactionIndex as unique identifier */
            return parentTransactionHash == other.parentTransactionHash
                   && transactionIndex == other.transactionIndex;
        }

        /* Converts the class to a json object */
        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.StartObject();
            {
                /* STEALTH ADDRESS REMOVAL: keyImage field removed */

                writer.Key("amount");
                writer.Uint64(amount);

                writer.Key("blockHeight");
                writer.Uint64(blockHeight);

                writer.Key("transactionPublicKey");
                transactionPublicKey.toJSON(writer);

                writer.Key("transactionIndex");
                writer.Uint64(transactionIndex);

                writer.Key("globalOutputIndex");
                writer.Uint64(globalOutputIndex.value_or(0));

                writer.Key("key");
                key.toJSON(writer);

                writer.Key("spendHeight");
                writer.Uint64(spendHeight);

                writer.Key("unlockTime");
                writer.Uint64(unlockTime);

                writer.Key("parentTransactionHash");
                parentTransactionHash.toJSON(writer);

                /* STEALTH ADDRESS REMOVAL: privateEphemeral field removed */
            }
            writer.EndObject();
        }

        /* Initializes the class from a json string */
        void fromJSON(const JSONValue &j)
        {
            /* STEALTH ADDRESS REMOVAL: keyImage field removed */
            amount = getUint64FromJSON(j, "amount");
            blockHeight = getUint64FromJSON(j, "blockHeight");
            transactionPublicKey.fromString(getStringFromJSON(j, "transactionPublicKey"));
            transactionIndex = getUint64FromJSON(j, "transactionIndex");
            globalOutputIndex = getUint64FromJSON(j, "globalOutputIndex");
            key.fromString(getStringFromJSON(j, "key"));
            spendHeight = getUint64FromJSON(j, "spendHeight");
            unlockTime = getUint64FromJSON(j, "unlockTime");
            parentTransactionHash.fromString(getStringFromJSON(j, "parentTransactionHash"));

            /* STEALTH ADDRESS REMOVAL: privateEphemeral field removed - stealth address derived */
        }
    };

    /* Includes the owner of the input so we can sign the input with the
       correct keys */
    struct TxInputAndOwner
    {
        TxInputAndOwner(
            const TransactionInput input,
            const Crypto::PublicKey publicKey,
            const Crypto::SecretKey privateKey):
            input(input),
            publicKey(publicKey),
            privateKey(privateKey)
        {
        }

        TransactionInput input;

        Crypto::PublicKey publicKey;

        Crypto::SecretKey privateKey;
    };

    struct TransactionDestination
    {
        Crypto::PublicKey receiverPublicKey;
        /* The amount of the transaction output */
        uint64_t amount;
    };

    struct GlobalIndexKey
    {
        uint64_t index;
        Crypto::PublicKey key;
    };

    struct ObscuredInput
    {
        /* The outputs - in transparent system, only real outputs are used */
        std::vector<GlobalIndexKey> outputs;

        /* The index of the real output in the outputs vector */
        uint64_t realOutput;

        /* The real transaction public key */
        Crypto::PublicKey realTransactionPublicKey;

        /* The index in the transaction outputs vector */
        uint64_t realOutputTransactionIndex;

        /* The amount being sent */
        uint64_t amount;

        /* The owners keys, so we can sign the input correctly */
        Crypto::PublicKey ownerPublicKey;
        Crypto::SecretKey ownerPrivateKey;
        Crypto::Hash parentTransactionHash;

        /* STEALTH ADDRESS REMOVAL: keyImage removed - was used for double-spend protection */
        /* STEALTH ADDRESS REMOVAL: privateEphemeral removed - derived from stealth address */
    };

    class Transaction
    {
      public:
        //////////////////
        /* Constructors */
        //////////////////

        Transaction() {};

        Transaction(
            /* Mapping of public key to transaction amount, can be multiple
               if one transaction sends to multiple subwallets */
            const std::unordered_map<Crypto::PublicKey, int64_t> transfers,
            const Crypto::Hash hash,
            const uint64_t fee,
            const uint64_t timestamp,
            const uint64_t blockHeight,
            const uint64_t unlockTime,
            const bool isCoinbaseTransaction,
            const bool isStakingTransaction = false):
            transfers(transfers),
            hash(hash),
            fee(fee),
            timestamp(timestamp),
            blockHeight(blockHeight),
            unlockTime(unlockTime),
            isCoinbaseTransaction(isCoinbaseTransaction),
            isStakingTransaction(isStakingTransaction)
        {
        }

        /////////////////////////////
        /* Public member functions */
        /////////////////////////////

        int64_t totalAmount() const
        {
            int64_t sum = 0;
            for (const auto [pubKey, amount] : transfers)
            {
                sum += amount;
            }
            return sum;
        }

        /////////////////////////////
        /* Public member variables */
        /////////////////////////////

        /* A map of public keys to amounts, since one transaction can go to
           multiple addresses. These can be positive or negative, for example
           one address might have sent 10,000 TRTL (-10000) to two recipients
           (+5000), (+5000)

           All the public keys in this map, are ones that the wallet container
           owns, it won't store amounts belonging to random people */
        std::unordered_map<Crypto::PublicKey, int64_t> transfers;

        /* The hash of the transaction */
        Crypto::Hash hash;

        /* The fee the transaction was sent with (always positive) */
        uint64_t fee;

        /* The blockheight this transaction is in */
        uint64_t blockHeight;

        /* The timestamp of this transaction (taken from the block timestamp) */
        uint64_t timestamp;

        /* When does the transaction unlock */
        uint64_t unlockTime;

        /* Was this transaction a miner reward / coinbase transaction */
        bool isCoinbaseTransaction;

        /* Was this transaction a staking transaction */
        bool isStakingTransaction = false;

        /* Converts the class to a json object */
        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.StartObject();
            writer.Key("transfers");
            writer.StartArray();
            for (const auto &[publicKey, amount] : transfers)
            {
                writer.StartObject();
                writer.Key("publicKey");
                publicKey.toJSON(writer);
                writer.Key("amount");
                writer.Int64(amount);
                writer.EndObject();
            }
            writer.EndArray();
            writer.Key("hash");
            hash.toJSON(writer);
            writer.Key("fee");
            writer.Uint64(fee);
            writer.Key("blockHeight");
            writer.Uint64(blockHeight);
            writer.Key("timestamp");
            writer.Uint64(timestamp);
            writer.Key("unlockTime");
            writer.Uint64(unlockTime);
            writer.Key("isCoinbaseTransaction");
            writer.Bool(isCoinbaseTransaction);
            writer.Key("isStakingTransaction");
            writer.Bool(isStakingTransaction);
            writer.EndObject();
        }

        /* Initializes the class from a json string */
        void fromJSON(const JSONValue &j)
        {
            for (const auto &x : getArrayFromJSON(j, "transfers"))
            {
                Crypto::PublicKey publicKey;
                publicKey.fromString(getStringFromJSON(x, "publicKey"));
                transfers[publicKey] = getInt64FromJSON(x, "amount");
            }
            hash.fromString(getStringFromJSON(j, "hash"));
            fee = getUint64FromJSON(j, "fee");
            blockHeight = getUint64FromJSON(j, "blockHeight");
            timestamp = getUint64FromJSON(j, "timestamp");
            unlockTime = getUint64FromJSON(j, "unlockTime");
            isCoinbaseTransaction = getBoolFromJSON(j, "isCoinbaseTransaction");

            // Handle backwards compatibility - isStakingTransaction may not exist in older wallets
            if (j.HasMember("isStakingTransaction"))
            {
                isStakingTransaction = getBoolFromJSON(j, "isStakingTransaction");
            }
        }
    };

    struct WalletStatus
    {
        /* The amount of blocks the wallet has synced */
        uint64_t walletBlockCount;
        /* The amount of blocks the daemon we are connected to has synced */
        uint64_t localDaemonBlockCount;
        /* The amount of blocks the daemons on the network have */
        uint64_t networkBlockCount;
        /* The amount of peers the node is connected to */
        uint32_t peerCount;
        /* The hashrate (based on the last block the daemon has synced) */
        uint64_t lastKnownHashrate;
    };

    /* A structure just used to display locked balance, due to change from
       sent transactions. We just need the amount and a unique identifier
       (hash+key), since we can't spend it, we don't need all the other stuff */
    struct UnconfirmedInput
    {
        /* The amount of the input */
        uint64_t amount;

        /* The transaction key we took from the key outputs */
        Crypto::PublicKey key;

        /* The transaction hash of the transaction that contains this input */
        Crypto::Hash parentTransactionHash;

        /* Converts the class to a json object */
        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.StartObject();
            writer.Key("amount");
            writer.Uint64(amount);
            writer.Key("key");
            key.toJSON(writer);
            writer.Key("parentTransactionHash");
            parentTransactionHash.toJSON(writer);
            writer.EndObject();
        }

        /* Initializes the class from a json string */
        void fromJSON(const JSONValue &j)
        {
            amount = getUint64FromJSON(j, "amount");
            key.fromString(getStringFromJSON(j, "key"));
            parentTransactionHash.fromString(getStringFromJSON(j, "parentTransactionHash"));
        }
    };

    struct TopBlock
    {
        Crypto::Hash hash;
        uint64_t height;
    };

    class FeeType
    {
        public:
            /* Fee will be specified as fee per byte, for example, 1 atomic TRTL per byte. */
            bool isFeePerByte = false;

            /* Fee for each byte, in atomic units. Allowed to be a double, since
             * we will truncate it to an int upon performing the chunking. */
            double feePerByte = 0;

            /* Fee will be specified as a fixed fee */
            bool isFixedFee = false;

            /* Total fee to use */
            uint64_t fixedFee = 0;

            /* Fee will not be specified, use the minimum possible */
            bool isMinimumFee = false;

            static FeeType MinimumFee()
            {
                FeeType fee;
                fee.isMinimumFee = true;
                return fee;
            }

            static FeeType FeePerByte(const double feePerByte)
            {
                FeeType fee;
                fee.isFeePerByte = true;
                fee.feePerByte = feePerByte;
                return fee;
            }

            static FeeType FixedFee(const uint64_t fixedFee)
            {
                FeeType fee;
                fee.isFixedFee = true;
                fee.fixedFee = fixedFee;
                return fee;
            }

        private:
            FeeType() = default;
    };

    struct TransactionResult
    {
        /* The error, if any */
        Error error;

        /* The raw transaction */
        Pastella::Transaction transaction;

        /* The transaction outputs, before converted into boost uglyness, used
           for determining key inputs from the tx that belong to us */
        std::vector<WalletTypes::KeyOutput> outputs;

        /* The random key pair we generated */
        Pastella::KeyPair txKeyPair;
    };

    struct PreparedTransactionInfo
    {
        uint64_t fee;
        std::vector<WalletTypes::TxInputAndOwner> inputs;
        std::string changeAddress;
        uint64_t changeRequired;
        TransactionResult tx;
        Crypto::Hash transactionHash;
    };

    struct StakeInfo
    {
        /* The staking transaction hash */
        Crypto::Hash stakingTxHash;

        /* The amount staked */
        uint64_t amount;

        /* The unlock time when funds can be withdrawn */
        uint64_t unlockTime;

        /* The duration in days funds were locked for */
        uint32_t lockDurationDays;

        /* The address that owns the stake */
        std::string address;

        /* The current block height */
        uint64_t currentHeight;

        /* Whether the stake is currently active (not unstaked) */
        bool isActive;

        /* The accumulated rewards (calculated on demand) */
        uint64_t pendingRewards;

        /* Enhanced reward calculation fields */
        uint64_t blocksStaked;
        uint64_t dailyRewardRate;
        uint64_t estDailyReward;
        uint64_t estWeeklyReward;
        uint64_t estMonthlyReward;
        uint64_t estYearlyReward;
        uint64_t accumulatedEarnings; /* Total earned so far */

        /* The reward address where staking rewards are sent */
        std::string rewardAddress;

        /* Converts the class to a json object */
        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.StartObject();
            writer.Key("stakingTxHash");
            stakingTxHash.toJSON(writer);
            writer.Key("amount");
            writer.Uint64(amount);
            writer.Key("unlockTime");
            writer.Uint64(unlockTime);
            writer.Key("lockDurationDays");
            writer.Uint64(lockDurationDays);
            writer.Key("currentHeight");
            writer.Uint64(currentHeight);
            writer.Key("isActive");
            writer.Bool(isActive);
            writer.Key("pendingRewards");
            writer.Uint64(pendingRewards);

            /* Enhanced reward calculation fields */
            writer.Key("blocksStaked");
            writer.Uint64(blocksStaked);
            writer.Key("dailyRewardRate");
            writer.Uint64(dailyRewardRate);
            writer.Key("estDailyReward");
            writer.Uint64(estDailyReward);
            writer.Key("estWeeklyReward");
            writer.Uint64(estWeeklyReward);
            writer.Key("estMonthlyReward");
            writer.Uint64(estMonthlyReward);
            writer.Key("estYearlyReward");
            writer.Uint64(estYearlyReward);
            writer.Key("rewardAddress");
            writer.String(rewardAddress);
            writer.EndObject();
        }

        /* Initializes the class from a json string */
        void fromJSON(const JSONValue &j)
        {
            stakingTxHash.fromString(getStringFromJSON(j, "stakingTxHash"));
            amount = getUint64FromJSON(j, "amount");
            unlockTime = getUint64FromJSON(j, "unlockTime");
            lockDurationDays = static_cast<uint32_t>(getUint64FromJSON(j, "lockDurationDays"));
            address = getStringFromJSON(j, "address");
            currentHeight = getUint64FromJSON(j, "currentHeight");
            isActive = getBoolFromJSON(j, "isActive");
            pendingRewards = getUint64FromJSON(j, "pendingRewards");
            rewardAddress = getStringFromJSON(j, "rewardAddress");
        }
    };

    /* Governance Proposal Structure */
    struct GovernanceProposal
    {
        uint64_t proposalId;
        std::string title;
        std::string description;
        std::string proposerAddress;
        uint64_t creationHeight;
        uint64_t expirationHeight;
        uint8_t proposalType; /* 0=parameter, 1=upgrade, 2=treasury */
        bool isActive;
        uint64_t votesFor;
        uint64_t votesAgainst;
        uint64_t totalVotingPower;
        std::string result; /* "passed", "failed", "active", "pending" */
        uint64_t amount; /* Treasury amount requested (only for type 2) */
        std::string recipientAddress; /* Treasury recipient (only for type 2) */

        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.StartObject();
            writer.Key("proposalId");
            writer.Uint64(proposalId);
            writer.Key("title");
            writer.String(title);
            writer.Key("description");
            writer.String(description);
            writer.Key("proposerAddress");
            writer.String(proposerAddress);
            writer.Key("creationHeight");
            writer.Uint64(creationHeight);
            writer.Key("expirationHeight");
            writer.Uint64(expirationHeight);
            writer.Key("proposalType");
            writer.Uint64(proposalType);
            writer.Key("isActive");
            writer.Bool(isActive);
            writer.Key("votesFor");
            writer.Uint64(votesFor);
            writer.Key("votesAgainst");
            writer.Uint64(votesAgainst);
            writer.Key("totalVotingPower");
            writer.Uint64(totalVotingPower);
            writer.Key("result");
            writer.String(result);
            writer.Key("amount");
            writer.Uint64(amount);
            writer.Key("recipientAddress");
            writer.String(recipientAddress);
            writer.EndObject();
        }

        void fromJSON(const nlohmann::json &j)
        {
            proposalId = j.at("proposalId").get<uint64_t>();
            title = j.at("title").get<std::string>();
            description = j.at("description").get<std::string>();
            proposerAddress = j.at("proposerAddress").get<std::string>();
            creationHeight = j.at("creationHeight").get<uint64_t>();
            expirationHeight = j.at("expirationHeight").get<uint64_t>();
            proposalType = j.at("proposalType").get<uint8_t>();
            isActive = j.at("isActive").get<bool>();
            votesFor = j.at("votesFor").get<uint64_t>();
            votesAgainst = j.at("votesAgainst").get<uint64_t>();
            totalVotingPower = j.at("totalVotingPower").get<uint64_t>();
            result = j.at("result").get<std::string>();

            /* Handle optional fields for backward compatibility */
            amount = j.value("amount", 0);
            recipientAddress = j.value("recipientAddress", "");
        }
    };

    /* Governance Vote Structure */
    struct GovernanceVote
    {
        uint64_t proposalId;
        std::string voterAddress;
        uint8_t vote; /* 0=against, 1=for, 2=abstain */
        uint64_t stakeWeight;
        uint64_t voteHeight;

        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.StartObject();
            writer.Key("proposalId");
            writer.Uint64(proposalId);
            writer.Key("voterAddress");
            writer.String(voterAddress);
            writer.Key("vote");
            writer.Uint64(vote);
            writer.Key("stakeWeight");
            writer.Uint64(stakeWeight);
            writer.Key("voteHeight");
            writer.Uint64(voteHeight);
            writer.EndObject();
        }

        void fromJSON(const nlohmann::json &j)
        {
            proposalId = j.at("proposalId").get<uint64_t>();
            voterAddress = j.at("voterAddress").get<std::string>();
            vote = j.at("vote").get<uint8_t>();
            stakeWeight = j.at("stakeWeight").get<uint64_t>();
            voteHeight = j.at("voteHeight").get<uint64_t>();
        }
    };

    inline void to_json(nlohmann::json &j, const TopBlock &t)
    {
        j = {{"hash", t.hash}, {"height", t.height}};
    }

    inline void from_json(const nlohmann::json &j, TopBlock &t)
    {
        t.hash = j.at("hash").get<Crypto::Hash>();
        t.height = j.at("height").get<uint64_t>();
    }

    inline void to_json(nlohmann::json &j, const WalletBlockInfo &w)
    {
        j = {{"transactions", w.transactions},
             {"blockHeight", w.blockHeight},
             {"blockHash", w.blockHash},
             {"blockTimestamp", w.blockTimestamp}};
        if (w.coinbaseTransaction)
        {
            j["coinbaseTX"] = *(w.coinbaseTransaction);
        }
    }

    inline void from_json(const nlohmann::json &j, WalletBlockInfo &w)
    {
        if (j.find("coinbaseTX") != j.end())
        {
            w.coinbaseTransaction = j.at("coinbaseTX").get<RawCoinbaseTransaction>();
        }
        w.transactions = j.at("transactions").get<std::vector<RawTransaction>>();
        w.blockHeight = j.at("blockHeight").get<uint64_t>();
        w.blockHash = j.at("blockHash").get<Crypto::Hash>();
        w.blockTimestamp = j.at("blockTimestamp").get<uint64_t>();
    }

    inline void to_json(nlohmann::json &j, const RawCoinbaseTransaction &r)
    {
        j = {{"outputs", r.keyOutputs},
             {"hash", r.hash},
             {"txPublicKey", r.transactionPublicKey},
             {"unlockTime", r.unlockTime}};
    }

    inline void from_json(const nlohmann::json &j, RawCoinbaseTransaction &r)
    {
        r.keyOutputs = j.at("outputs").get<std::vector<KeyOutput>>();
        r.hash = j.at("hash").get<Crypto::Hash>();
        r.transactionPublicKey = j.at("txPublicKey").get<Crypto::PublicKey>();

        /* We need to try to get the unlockTime from an integer in the json
           however, if that fails because we're talking to a blockchain
           cache API that encodes unlockTime as a string (due to json
           integer encoding limits), we need to attempt this as a string */
        try
        {
            r.unlockTime = j.at("unlockTime").get<uint64_t>();
        }
        catch (const nlohmann::json::exception &)
        {
            r.unlockTime = std::stoull(j.at("unlockTime").get<std::string>());
        }
    }

    inline void to_json(nlohmann::json &j, const RawTransaction &r)
    {
        j = {{"outputs", r.keyOutputs},
             {"hash", r.hash},
             {"txPublicKey", r.transactionPublicKey},
             {"unlockTime", r.unlockTime},
             {"inputs", r.keyInputs}};
    }

    inline void from_json(const nlohmann::json &j, RawTransaction &r)
    {
        r.keyOutputs = j.at("outputs").get<std::vector<KeyOutput>>();
        r.hash = j.at("hash").get<Crypto::Hash>();
        r.transactionPublicKey = j.at("txPublicKey").get<Crypto::PublicKey>();

        /* We need to try to get the unlockTime from an integer in the json
           however, if that fails because we're talking to a blockchain
           cache API that encodes unlockTime as a string (due to json
           integer encoding limits), we need to attempt this as a string */
        try
        {
            r.unlockTime = j.at("unlockTime").get<uint64_t>();
        }
        catch (const nlohmann::json::exception &)
        {
            r.unlockTime = std::stoull(j.at("unlockTime").get<std::string>());
        }
        r.keyInputs = j.at("inputs").get<std::vector<Pastella::KeyInput>>();
    }

    inline void to_json(nlohmann::json &j, const KeyOutput &k)
    {
        j = {{"key", k.key}, {"amount", k.amount}};
    }

    inline void from_json(const nlohmann::json &j, KeyOutput &k)
    {
        k.key = j.at("key").get<Crypto::PublicKey>();
        k.amount = j.at("amount").get<uint64_t>();

        /* If we're talking to a daemon or blockchain cache
           that returns the globalIndex as part of the structure
           of a key output, then we need to load that into the
           data structure. */
        if (j.find("globalIndex") != j.end())
        {
            k.globalOutputIndex = j.at("globalIndex").get<uint64_t>();
        }
    }

    inline void to_json(nlohmann::json &j, const UnconfirmedInput &u)
    {
        j = {{"amount", u.amount}, {"key", u.key}, {"parentTransactionHash", u.parentTransactionHash}};
    }

    inline void from_json(const nlohmann::json &j, UnconfirmedInput &u)
    {
        u.amount = j.at("amount").get<uint64_t>();
        u.key = j.at("key").get<Crypto::PublicKey>();
        u.parentTransactionHash = j.at("parentTransactionHash").get<Crypto::Hash>();
    }

    inline void to_json(nlohmann::json &j, const StakeInfo &s)
    {
        j = {{"stakingTxHash", s.stakingTxHash},
             {"amount", s.amount},
             {"unlockTime", s.unlockTime},
             {"lockDurationDays", s.lockDurationDays},
             {"address", s.address},
             {"currentHeight", s.currentHeight},
             {"isActive", s.isActive},
             {"pendingRewards", s.pendingRewards},
             {"rewardAddress", s.rewardAddress}};
    }

    inline void from_json(const nlohmann::json &j, StakeInfo &s)
    {
        s.stakingTxHash = j.at("stakingTxHash").get<Crypto::Hash>();
        s.amount = j.at("amount").get<uint64_t>();
        s.unlockTime = j.at("unlockTime").get<uint64_t>();
        s.lockDurationDays = j.at("lockDurationDays").get<uint32_t>();
        s.address = j.at("address").get<std::string>();
        s.currentHeight = j.at("currentHeight").get<uint64_t>();
        s.isActive = j.at("isActive").get<bool>();
        s.pendingRewards = j.at("pendingRewards").get<uint64_t>();
        s.rewardAddress = j.at("rewardAddress").get<std::string>();
    }
}
