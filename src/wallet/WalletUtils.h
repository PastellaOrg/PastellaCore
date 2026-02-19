// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "WalletGreenTypes.h"
#include "pastellacore/Currency.h"
#include "wallet/WalletGreen.h"

#include <string>

namespace Pastella
{
    uint64_t getDefaultMixinByHeight(const uint64_t height);

    void throwIfKeysMismatch(
        const Crypto::SecretKey &secretKey,
        const Crypto::PublicKey &expectedPublicKey,
        const std::string &message = "");

    bool validateAddress(const std::string &address, const Pastella::Currency &currency);

    std::ostream &operator<<(std::ostream &os, Pastella::WalletTransactionState state);

    std::ostream &operator<<(std::ostream &os, Pastella::WalletTransferType type);

    std::ostream &operator<<(std::ostream &os, Pastella::WalletGreen::WalletState state);

    class TransferListFormatter
    {
      public:
        explicit TransferListFormatter(const Pastella::Currency &currency, const WalletGreen::TransfersRange &range);

        void print(std::ostream &os) const;

        friend std::ostream &operator<<(std::ostream &os, const TransferListFormatter &formatter);

      private:
        const Pastella::Currency &m_currency;

        const WalletGreen::TransfersRange &m_range;
    };

    class WalletOrderListFormatter
    {
      public:
        explicit WalletOrderListFormatter(
            const Pastella::Currency &currency,
            const std::vector<Pastella::WalletOrder> &walletOrderList);

        void print(std::ostream &os) const;

        friend std::ostream &operator<<(std::ostream &os, const WalletOrderListFormatter &formatter);

      private:
        const Pastella::Currency &m_currency;

        const std::vector<Pastella::WalletOrder> &m_walletOrderList;
    };

} // namespace Pastella
