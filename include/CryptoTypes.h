// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "json.hpp"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <algorithm>
#include <common/StringTools.h>
#include <cstdint>
#include <iterator>

namespace Crypto
{
    struct Hash
    {
        /* Can't have constructors here, because it violates std::is_pod<>
           which is used somewhere */
        bool operator==(const Hash &other) const
        {
            return std::equal(std::begin(data), std::end(data), std::begin(other.data));
        }

        bool operator!=(const Hash &other) const
        {
            return !(*this == other);
        }

        uint8_t data[32];

        /* Converts the class to a json object */
        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.String(Common::podToHex(data));
        }

        /* Initializes the class from a json string */
        void fromString(const std::string &s)
        {
            if (!Common::podFromHex(s, data))
            {
                throw std::invalid_argument("Error parsing JSON Hash, wrong length or not hex");
            }
        }
    };

    struct PublicKey
    {
        PublicKey() {}

        PublicKey(std::initializer_list<uint8_t> input)
        {
            std::copy(input.begin(), input.end(), std::begin(data));
        }

        PublicKey(const uint8_t input[32])
        {
            std::copy(input, input + 32, std::begin(data));
        }

        bool operator==(const PublicKey &other) const
        {
            return std::equal(std::begin(data), std::end(data), std::begin(other.data));
        }

        bool operator!=(const PublicKey &other) const
        {
            return !(*this == other);
        }

        /* Converts the class to a json object */
        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.String(Common::podToHex(data));
        }

        /* Initializes the class from a json string */
        void fromString(const std::string &s)
        {
            if (!Common::podFromHex(s, data))
            {
                throw std::invalid_argument("Error parsing JSON PublicKey, wrong length or not hex");
            }
        }

        uint8_t data[32];
    };

    struct SecretKey
    {
        SecretKey() {}

        SecretKey(std::initializer_list<uint8_t> input)
        {
            std::copy(input.begin(), input.end(), std::begin(data));
        }

        SecretKey(const uint8_t input[32])
        {
            std::copy(input, input + 32, std::begin(data));
        }

        bool operator==(const SecretKey &other) const
        {
            return std::equal(std::begin(data), std::end(data), std::begin(other.data));
        }

        bool operator!=(const SecretKey &other) const
        {
            return !(*this == other);
        }

        /* Converts the class to a json object */
        void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
        {
            writer.String(Common::podToHex(data));
        }

        /* Initializes the class from a json string */
        void fromString(const std::string &s)
        {
            if (!Common::podFromHex(s, data))
            {
                throw std::invalid_argument("Error parsing JSON SecretKey, wrong length or not hex");
            }
        }

        uint8_t data[32];
    };

    /* STEALTH ADDRESS REMOVAL: KeyDerivation and KeyImage structs removed
     * KeyDerivation was used for stealth address shared secret
     * KeyImage was used for stealth double-spend protection (replaced by UTXO tracking) */

    struct Signature
    {
        Signature() {}

        Signature(std::initializer_list<uint8_t> input)
        {
            std::copy(input.begin(), input.end(), std::begin(data));
        }

        Signature(const uint8_t input[64])
        {
            std::copy(input, input + 64, std::begin(data));
        }

        bool operator==(const Signature &other) const
        {
            return std::equal(std::begin(data), std::end(data), std::begin(other.data));
        }

        bool operator!=(const Signature &other) const
        {
            return !(*this == other);
        }

        uint8_t data[64];
    };

    /* For boost hash_value */
    inline size_t hash_value(const Hash &hash)
    {
        return reinterpret_cast<const size_t &>(hash);
    }

    inline size_t hash_value(const PublicKey &publicKey)
    {
        return reinterpret_cast<const size_t &>(publicKey);
    }

    inline size_t hash_value(const SecretKey &secretKey)
    {
        return reinterpret_cast<const size_t &>(secretKey);
    }

    /* STEALTH ADDRESS REMOVAL: hash_value functions for KeyDerivation and KeyImage removed */

    inline void to_json(nlohmann::json &j, const Hash &h)
    {
        j = Common::podToHex(h);
    }

    inline void from_json(const nlohmann::json &j, Hash &h)
    {
        if (!Common::podFromHex(j.get<std::string>(), h.data))
        {
            const auto err = nlohmann::detail::parse_error::create(100, 0, "Wrong length or not hex!");

            throw nlohmann::json::parse_error(err);
        }
    }

    inline void to_json(nlohmann::json &j, const PublicKey &p)
    {
        j = Common::podToHex(p);
    }

    inline void from_json(const nlohmann::json &j, PublicKey &p)
    {
        if (!Common::podFromHex(j.get<std::string>(), p.data))
        {
            const auto err = nlohmann::detail::parse_error::create(100, 0, "Wrong length or not hex!");

            throw nlohmann::json::parse_error(err);
        }
    }

    inline void to_json(nlohmann::json &j, const SecretKey &s)
    {
        j = Common::podToHex(s);
    }

    inline void from_json(const nlohmann::json &j, SecretKey &s)
    {
        if (!Common::podFromHex(j.get<std::string>(), s.data))
        {
            const auto err = nlohmann::detail::parse_error::create(100, 0, "Wrong length or not hex!");

            throw nlohmann::json::parse_error(err);
        }
    }

    /* STEALTH ADDRESS REMOVAL: to_json/from_json functions for KeyDerivation and KeyImage removed */

} // namespace Crypto

namespace std
{
    /* For using in std::unordered_* containers */
    template<> struct hash<Crypto::Hash>
    {
        size_t operator()(const Crypto::Hash &hash) const
        {
            return reinterpret_cast<const size_t &>(hash);
        }
    };

    template<> struct hash<Crypto::PublicKey>
    {
        size_t operator()(const Crypto::PublicKey &publicKey) const
        {
            return reinterpret_cast<const size_t &>(publicKey);
        }
    };

    template<> struct hash<Crypto::SecretKey>
    {
        size_t operator()(const Crypto::SecretKey &secretKey) const
        {
            return reinterpret_cast<const size_t &>(secretKey);
        }
    };

    /* STEALTH ADDRESS REMOVAL: std::hash specializations for KeyDerivation and KeyImage removed */

    template<> struct hash<Crypto::Signature>
    {
        size_t operator()(const Crypto::Signature &signature) const
        {
            return reinterpret_cast<const size_t &>(signature);
        }
    };

    /* Overloading the << operator */
    inline ostream &operator<<(ostream &os, const Crypto::Hash &hash)
    {
        os << Common::podToHex(hash);
        return os;
    }

    inline ostream &operator<<(ostream &os, const Crypto::PublicKey &publicKey)
    {
        os << Common::podToHex(publicKey);
        return os;
    }

    inline ostream &operator<<(ostream &os, const Crypto::SecretKey &secretKey)
    {
        os << Common::podToHex(secretKey);
        return os;
    }

    /* STEALTH ADDRESS REMOVAL: stream operators for KeyDerivation and KeyImage removed */

    inline ostream &operator<<(ostream &os, const Crypto::Signature &signature)
    {
        os << Common::podToHex(signature);
        return os;
    }
} // namespace std
