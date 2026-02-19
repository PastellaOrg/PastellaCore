// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "hash.h"

#include <CryptoTypes.h>
#include <cstddef>
#include <limits>
#include <mutex>
#include <type_traits>
#include <vector>

namespace Crypto
{
    struct EllipticCurvePoint
    {
        uint8_t data[32];
    };

    struct EllipticCurveScalar
    {
        uint8_t data[32];
    };

    class crypto_ops
    {
        crypto_ops();

        crypto_ops(const crypto_ops &);

        void operator=(const crypto_ops &);

        ~crypto_ops();

        static void generate_keys(PublicKey &, SecretKey &);

        friend void generate_keys(PublicKey &, SecretKey &);

        static void generate_deterministic_keys(PublicKey &pub, SecretKey &sec, SecretKey &second);

        friend void generate_deterministic_keys(PublicKey &pub, SecretKey &sec, SecretKey &second);

        static SecretKey generate_m_keys(
            PublicKey &pub,
            SecretKey &sec,
            const SecretKey &recovery_key = SecretKey(),
            bool recover = false);

        friend SecretKey generate_m_keys(
            PublicKey &pub,
            SecretKey &sec,
            const SecretKey &recovery_key,
            bool recover);

        static bool check_key(const PublicKey &);

        friend bool check_key(const PublicKey &);

        static bool secret_key_to_public_key(const SecretKey &, PublicKey &);

        friend bool secret_key_to_public_key(const SecretKey &, PublicKey &);

        /* STEALTH ADDRESS REMOVAL: Key derivation functions removed
         * generate_key_derivation(), derive_public_key(), derive_secret_key(),
         * underive_public_key(), underive_public_key_and_get_scalar() removed */

        static void generate_signature(const Hash &, const PublicKey &, const SecretKey &, Signature &);

        friend void generate_signature(const Hash &, const PublicKey &, const SecretKey &, Signature &);

        static bool check_signature(const Hash &, const PublicKey &, const Signature &);

        friend bool check_signature(const Hash &, const PublicKey &, const Signature &);

        /* STEALTH ADDRESS REMOVAL: generate_key_image() removed - used for stealth double-spend protection */
        /* STEALTH ADDRESS REMOVAL: scalarmultKey() removed - used KeyImage type */


      public:
        static std::tuple<bool, std::vector<Signature>> generateRingSignatures(
            const Hash prefixHash,
            const PublicKey keyImage, /* Was KeyImage type, changed to PublicKey */
            const std::vector<PublicKey> publicKeys,
            const Crypto::SecretKey transactionSecretKey,
            uint64_t realOutput);

        static bool checkRingSignature(
            const Hash &prefix_hash,
            const PublicKey &image, /* Was KeyImage type, changed to PublicKey */
            const std::vector<PublicKey> pubs,
            const std::vector<Signature> signatures);

        static void hash_data_to_ec(const uint8_t *, std::size_t, PublicKey &);
    };

    /* Generate a new key pair */
    inline void generate_keys(PublicKey &pub, SecretKey &sec)
    {
        crypto_ops::generate_keys(pub, sec);
    }

    inline void generate_deterministic_keys(PublicKey &pub, SecretKey &sec, SecretKey &second)
    {
        crypto_ops::generate_deterministic_keys(pub, sec, second);
    }

    inline SecretKey generate_m_keys(
        PublicKey &pub,
        SecretKey &sec,
        const SecretKey &recovery_key = SecretKey(),
        bool recover = false)
    {
        return crypto_ops::generate_m_keys(pub, sec, recovery_key, recover);
    }

    /* Check a public key. Returns true if it is valid, false otherwise.
     */
    inline bool check_key(const PublicKey &key)
    {
        return crypto_ops::check_key(key);
    }

    /* Checks a private key and computes the corresponding public key.
     */
    inline bool secret_key_to_public_key(const SecretKey &sec, PublicKey &pub)
    {
        return crypto_ops::secret_key_to_public_key(sec, pub);
    }

    /* To generate an ephemeral key used to send money to:
     * * The sender generates a new key pair, which becomes the transaction key. The public transaction key is included
     * in "extra" field.
     * * Both the sender and the receiver generate key derivation from the transaction key and the receivers' "view"
     * key.
     * * The sender uses key derivation, the output index, and the receivers' "spend" key to derive an ephemeral public
     * key.
     * * The receiver can either derive the public key (to check that the transaction is addressed to him) or the
     * private key (to spend the money).
     */

    /* STEALTH ADDRESS REMOVAL: All key derivation wrapper functions removed
     * generate_key_derivation(), derive_public_key(), derive_secret_key(),
     * underive_public_key(), underive_public_key_and_get_scalar() removed */

    /* Generation and checking of a standard signature.
     */
    inline void generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec, Signature &sig)
    {
        crypto_ops::generate_signature(prefix_hash, pub, sec, sig);
    }

    inline bool check_signature(const Hash &prefix_hash, const PublicKey &pub, const Signature &sig)
    {
        return crypto_ops::check_signature(prefix_hash, pub, sig);
    }

    /* To send money to a key:
     * * The sender generates an ephemeral key and includes it in transaction output.
     * * To spend the money, the receiver generates a key image from it.
     * * In the original CryptoNote system, ring signatures were generated using multiple outputs.
     * * In the transparent system, we use direct ECDSA signatures instead.
     * To detect double spends, it is necessary to check that each key image is used at most once.
     */

    /* STEALTH ADDRESS REMOVAL: generate_key_image() and scalarmultKey() wrapper functions removed */

    inline void hash_data_to_ec(const uint8_t *data, std::size_t len, PublicKey &key)
    {
        crypto_ops::hash_data_to_ec(data, len, key);
    }
} // namespace Crypto
