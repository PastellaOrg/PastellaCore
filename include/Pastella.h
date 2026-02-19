// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "CryptoTypes.h"
#include "json.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"

#include <JsonHelper.h>
#include <boost/variant.hpp>
#include <common/StringTools.h>
#include <vector>

namespace Pastella
{
    struct BaseInput
    {
        uint32_t blockIndex;
    };
    struct KeyInput
    {
        uint64_t amount;
        std::vector<uint32_t> outputIndexes; /* In transparent system: single output index */

        /* TRANSPARENT SYSTEM: Explicit UTXO reference
         * Identifies which transaction output is being spent */
        Crypto::Hash transactionHash; /* Hash of transaction that created the UTXO */
        uint32_t outputIndex;         /* Index of the output in that transaction */

        /* STEALTH ADDRESS REMOVAL: KeyImage removed - was used for double-spend protection */
    };

    struct KeyOutput
    {
        Crypto::PublicKey key;
    };

    typedef boost::variant<BaseInput, KeyInput> TransactionInput;

    typedef boost::variant<KeyOutput> TransactionOutputTarget;

    struct TransactionOutput
    {
        uint64_t amount;
        TransactionOutputTarget target;
    };

    struct TransactionPrefix
    {
        uint8_t version;
        uint64_t unlockTime;
        std::vector<TransactionInput> inputs;
        std::vector<TransactionOutput> outputs;
        std::vector<uint8_t> extra;
    };

    struct Transaction : public TransactionPrefix
    {
        std::vector<std::vector<Crypto::Signature>> signatures;
    };

    struct BaseTransaction : public TransactionPrefix
    {
    };

    struct ParentBlock
    {
        uint8_t majorVersion;
        uint8_t minorVersion;
        Crypto::Hash previousBlockHash;
        uint16_t transactionCount;
        std::vector<Crypto::Hash> baseTransactionBranch;
        BaseTransaction baseTransaction;
        std::vector<Crypto::Hash> blockchainBranch;
    };

    struct BlockHeader
    {
        uint8_t majorVersion;
        uint8_t minorVersion;
        uint32_t nonce;
        uint64_t timestamp;
        Crypto::Hash previousBlockHash;
    };

    struct BlockTemplate : public BlockHeader
    {
        ParentBlock parentBlock;
        Transaction baseTransaction;
        std::vector<Crypto::Hash> transactionHashes;
    };

    struct AccountPublicAddress
    {
        Crypto::PublicKey publicKey;

    };

    struct AccountKeys
    {
        AccountPublicAddress address;
        Crypto::SecretKey secretKey;

    };

    struct KeyPair
    {
        Crypto::PublicKey publicKey;
        Crypto::SecretKey secretKey;
    };

    using BinaryArray = std::vector<uint8_t>;

    struct RawBlock
    {
        BinaryArray block; // BlockTemplate
        std::vector<BinaryArray> transactions;

        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.StartObject();
            writer.Key("block");
            writer.String(Common::toHex(block));

            writer.Key("transactions");
            writer.StartArray();
            for (auto transaction : transactions)
            {
                writer.String(Common::toHex(transaction));
            }
            writer.EndArray();
            writer.EndObject();
        }

        void fromJSON(const JSONValue &j)
        {
            block = Common::fromHex(getStringFromJSON(j, "block"));
            for (const auto &tx : getArrayFromJSON(j, "transactions"))
            {
                transactions.push_back(Common::fromHex(tx.GetString()));
            }
        }
    };

    inline void to_json(nlohmann::json &j, const Pastella::KeyInput &k)
    {
        /* STEALTH ADDRESS REMOVAL: k_image field removed */
        j = {{"amount", k.amount}, {"key_offsets", k.outputIndexes}};

        /* CRITICAL FIX: Include UTXO reference data for accurate spend detection
         * In transparent system, KeyInput explicitly identifies which UTXO is being spent */
        j["transactionHash"] = Common::podToHex(k.transactionHash);
        j["outputIndex"] = k.outputIndex;
    }

    inline void from_json(const nlohmann::json &j, Pastella::KeyInput &k)
    {
        k.amount = j.at("amount").get<uint64_t>();
        if (j.find("key_offsets") != j.end())
        {
            k.outputIndexes = j.at("key_offsets").get<std::vector<uint32_t>>();
        }

        /* CRITICAL FIX: Read UTXO reference data for accurate spend detection
         * In transparent system, KeyInput explicitly identifies which UTXO is being spent */
        if (j.find("transactionHash") != j.end())
        {
            k.transactionHash.fromString(j.at("transactionHash").get<std::string>());
        }
        if (j.find("outputIndex") != j.end())
        {
            k.outputIndex = j.at("outputIndex").get<uint32_t>();
        }

        /* STEALTH ADDRESS REMOVAL: k_image field removed */
    }

    inline void to_json(nlohmann::json &j, const Pastella::RawBlock &block)
    {
        std::vector<std::string> transactions;

        for (auto transaction : block.transactions)
        {
            transactions.push_back(Common::toHex(transaction));
        }

        j = {{"block", Common::toHex(block.block)}, {"transactions", transactions}};
    }

    inline void from_json(const nlohmann::json &j, Pastella::RawBlock &block)
    {
        block.transactions.clear();

        std::string blockString = j.at("block").get<std::string>();

        block.block = Common::fromHex(blockString);

        std::vector<std::string> transactions = j.at("transactions").get<std::vector<std::string>>();

        for (const auto transaction : transactions)
        {
            block.transactions.push_back(Common::fromHex(transaction));
        }
    }

} // namespace Pastella
