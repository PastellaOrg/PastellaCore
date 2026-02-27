// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "WalletUtils.h"

#include "Pastella.h"
#include "crypto/crypto.h"
#include "wallet/WalletErrors.h"

namespace Pastella
{
    void throwIfKeysMismatch(
        const Crypto::SecretKey &secretKey,
        const Crypto::PublicKey &expectedPublicKey,
        const std::string &message)
    {
        Crypto::PublicKey pub;
        bool r = Crypto::secret_key_to_public_key(secretKey, pub);
        if (!r || expectedPublicKey != pub)
        {
            throw std::system_error(make_error_code(Pastella::error::WRONG_PASSWORD), message);
        }
    }

    bool validateAddress(const std::string &address, const Pastella::Currency &currency)
    {
        Pastella::AccountPublicAddress ignore;
        return currency.parseAccountAddressString(address, ignore);
    }

    std::ostream &operator<<(std::ostream &os, Pastella::WalletTransactionState state)
    {
        switch (state)
        {
            case Pastella::WalletTransactionState::SUCCEEDED:
                os << "SUCCEEDED";
                break;
            case Pastella::WalletTransactionState::FAILED:
                os << "FAILED";
                break;
            case Pastella::WalletTransactionState::CANCELLED:
                os << "CANCELLED";
                break;
            case Pastella::WalletTransactionState::CREATED:
                os << "CREATED";
                break;
            case Pastella::WalletTransactionState::DELETED:
                os << "DELETED";
                break;
            default:
                os << "<UNKNOWN>";
        }

        return os << " (" << static_cast<int>(state) << ')';
    }

    std::ostream &operator<<(std::ostream &os, Pastella::WalletTransferType type)
    {
        switch (type)
        {
            case Pastella::WalletTransferType::USUAL:
                os << "USUAL";
                break;
            case Pastella::WalletTransferType::DONATION:
                os << "DONATION";
                break;
            case Pastella::WalletTransferType::CHANGE:
                os << "CHANGE";
                break;
            default:
                os << "<UNKNOWN>";
        }

        return os << " (" << static_cast<int>(type) << ')';
    }

    std::ostream &operator<<(std::ostream &os, Pastella::WalletGreen::WalletState state)
    {
        switch (state)
        {
            case Pastella::WalletGreen::WalletState::INITIALIZED:
                os << "INITIALIZED";
                break;
            case Pastella::WalletGreen::WalletState::NOT_INITIALIZED:
                os << "NOT_INITIALIZED";
                break;
            default:
                os << "<UNKNOWN>";
        }

        return os << " (" << static_cast<int>(state) << ')';
    }

    TransferListFormatter::TransferListFormatter(
        const Pastella::Currency &currency,
        const WalletGreen::TransfersRange &range):
        m_currency(currency),
        m_range(range)
    {
    }

    void TransferListFormatter::print(std::ostream &os) const
    {
        for (auto it = m_range.first; it != m_range.second; ++it)
        {
            os << '\n'
               << std::setw(21) << m_currency.formatAmount(it->second.amount) << ' '
               << (it->second.address.empty() ? "<UNKNOWN>" : it->second.address) << ' ' << it->second.type;
        }
    }

    std::ostream &operator<<(std::ostream &os, const TransferListFormatter &formatter)
    {
        formatter.print(os);
        return os;
    }

    WalletOrderListFormatter::WalletOrderListFormatter(
        const Pastella::Currency &currency,
        const std::vector<Pastella::WalletOrder> &walletOrderList):
        m_currency(currency),
        m_walletOrderList(walletOrderList)
    {
    }

    void WalletOrderListFormatter::print(std::ostream &os) const
    {
        os << '{';

        if (!m_walletOrderList.empty())
        {
            os << '<' << m_currency.formatAmount(m_walletOrderList.front().amount) << ", "
               << m_walletOrderList.front().address << '>';

            for (auto it = std::next(m_walletOrderList.begin()); it != m_walletOrderList.end(); ++it)
            {
                os << '<' << m_currency.formatAmount(it->amount) << ", " << it->address << '>';
            }
        }

        os << '}';
    }

    std::ostream &operator<<(std::ostream &os, const WalletOrderListFormatter &formatter)
    {
        formatter.print(os);
        return os;
    }

} // namespace Pastella
