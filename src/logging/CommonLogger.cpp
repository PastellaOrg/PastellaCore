// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "CommonLogger.h"
#include <iomanip>
#include <sstream>

namespace Logging
{
    namespace
    {
        std::string getLevelColor(Level level)
        {
            switch (level)
            {
                case FATAL:
                    return BRIGHT_RED;
                case ERROR:
                    return RED;
                case WARNING:
                    return BRIGHT_YELLOW;
                case INFO:
                    return BRIGHT_GREEN;
                case DEBUGGING:
                    return CYAN;
                case TRACE:
                    return GRAY;
                default:
                    return DEFAULT;
            }
        }

        std::string getCategoryColor(const std::string &category)
        {
            // Extract parent category (before first dot)
            std::string parent = category;
            size_t dotPos = category.find('.');
            if (dotPos != std::string::npos)
            {
                parent = category.substr(0, dotPos);
            }

            // Color by parent category
            if (parent == "Daemon" || parent == "daemon") return BRIGHT_BLUE;
            if (parent == "Core") return BRIGHT_CYAN;
            if (parent == "Database" || parent == "LevelDBWrapper") return BRIGHT_MAGENTA;
            if (parent == "RocksDBWrapper") return BRIGHT_WHITE;
            if (parent == "P2P" || parent == "NodeServer" || parent == "P2p") return BRIGHT_YELLOW;
            if (parent == "Wallet" || parent == "WalletGreen" || parent == "WalletBackend" || parent == "WalletService" || parent == "PaymentGateService") return GREEN;
            if (parent == "RPC" || parent == "DaemonRPC" || parent == "Http") return YELLOW;
            if (parent == "Mining" || parent == "Miner") return MAGENTA;
            if (parent == "Crypto") return CYAN;
            if (parent == "Blockchain") return CYAN;
            if (parent == "Staking" || parent == "StakingSystem") return BRIGHT_RED;
            return WHITE; // Default for unknown categories
        }

        std::string formatPattern(
            const std::string &pattern,
            const std::string &category,
            Level level,
            boost::posix_time::ptime time)
        {
            std::stringstream s;

            for (const char *p = pattern.c_str(); p && *p != 0; ++p)
            {
                if (*p == '%')
                {
                    ++p;
                    switch (*p)
                    {
                        case 0:
                            break;
                        case 'C':
                            {
                                s << "  " << getCategoryColor(category) << "[" << (category.empty() ? "UNKNOWN" : category) << "]" << DEFAULT;
                                // Add spacing to align columns (roughly 20 chars total for category + brackets)
                                int categoryLen = category.empty() ? 7 : category.length();
                                int spacesNeeded = std::max(0, 20 - categoryLen - 2); // 2 for brackets
                                s << std::string(spacesNeeded, ' ');
                            }
                            break;
                        case 'D':
                            {
                                auto date = time.date();
                                // Format: DD-MM-YYYY
                                s << DEFAULT << "["
                                  << std::setfill('0') << std::setw(2) << date.day() << "-"
                                  << std::setfill('0') << std::setw(2) << static_cast<int>(date.month()) << "-"
                                  << date.year() << "]";
                            }
                            break;
                        case 'T':
                        {
                            auto timeOfDay = time.time_of_day();
                            long totalMicroseconds = time.time_of_day().total_microseconds();
                            long microseconds = totalMicroseconds % 1000000;
                            s << std::setfill('0') << std::setw(2) << timeOfDay.hours() << ":"
                              << std::setfill('0') << std::setw(2) << timeOfDay.minutes() << ":"
                              << std::setfill('0') << std::setw(2) << timeOfDay.seconds()
                              << GRAY << "." << std::setfill('0') << std::setw(6) << microseconds << "]" << DEFAULT;
                            break;
                        }
                        case 'f':
                        {
                            // Microseconds (6 digits) - handled in %T
                            break;
                        }
                        case 'L':
                            {
                                std::string levelName = ILogger::LEVEL_NAMES[level];
                                s << " " << getLevelColor(level) << "[" << levelName << "]" << DEFAULT;
                                // Add spacing to align level column - all levels should have same total width
                                // Target: [INFO]XX or [DEBUG]X where X is space, so target = 9 chars total
                                int levelLen = levelName.length();
                                int spacesNeeded = std::max(0, 9 - levelLen - 2); // 9 = target width
                                s << std::string(spacesNeeded, ' ');
                            }
                            break;
                        default:
                            s << *p;
                    }
                }
                else
                {
                    s << *p;
                }
            }

            return s.str();
        }

    } // namespace

    void CommonLogger::
        operator()(const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body)
    {
        if (level <= logLevel && disabledCategories.count(category) == 0)
        {
            std::string body2 = body;
            if (!pattern.empty())
            {
                std::string formattedPattern = formatPattern(pattern, category, level, time);
                // Insert pattern at the beginning, before any color tokens
                body2.insert(0, formattedPattern + " ");
            }

            doLogString(body2);
        }
    }

    void CommonLogger::setPattern(const std::string &pattern)
    {
        this->pattern = pattern;
    }

    void CommonLogger::disableCategory(const std::string &category)
    {
        disabledCategories.insert(category);
    }

    void CommonLogger::setMaxLevel(Level level)
    {
        logLevel = level;
    }

    CommonLogger::CommonLogger(Level level): logLevel(level), pattern("%D %T %L %C") {}

    void CommonLogger::doLogString(const std::string &message) {}

} // namespace Logging
