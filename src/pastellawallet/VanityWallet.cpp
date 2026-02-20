// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

/////////////////////////////////
#include <pastellawallet/VanityWallet.h>
/////////////////////////////////

#include <common/StringTools.h>
#include <config/PastellaConfig.h>
#include <config/WalletConfig.h>
#include <crypto/crypto.h>
#include <iostream>
#include <utilities/Addresses.h>
#include <utilities/ColouredMsg.h>
#include <utilities/FormatTools.h>
#include <utilities/String.h>
#include <walletbackend/WalletBackend.h>
#include <pastellawallet/Open.h>
#include <pastellawallet/Utilities.h>

#include <chrono>
#include <cstring>
#ifndef _WIN32
#include <poll.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include <conio.h>
#endif

/* Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz */
/* Notice: No '0' (zero), 'O' (capital o), 'I' (capital i), 'l' (lowercase L) */
const std::string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Format number with thousands separators */
std::string formatNumber(uint64_t num)
{
    std::string str = std::to_string(num);
    int n = str.length() - 3;

    while (n > 0)
    {
        str.insert(n, ",");
        n -= 3;
    }

    return str;
}

/* Global flag for signal handling */
static std::atomic<bool> g_cancelFlag(false);

/* Validate that string only contains Base58 characters */
bool isValidBase58(const std::string &str)
{
    if (str.empty())
    {
        return false;
    }

    for (char c : str)
    {
        if (BASE58_ALPHABET.find(c) == std::string::npos)
        {
            return false;
        }
    }

    return true;
}

/* Check for ambiguous characters (0, O, I, l) */
bool hasAmbiguousChars(const std::string &str)
{
    return str.find('0') != std::string::npos ||
           str.find('O') != std::string::npos ||
           str.find('I') != std::string::npos ||
           str.find('l') != std::string::npos;
}

/* Check pattern and return warnings/errors */
std::string checkPattern(const std::string &pattern)
{
    if (pattern.empty())
    {
        return "Error: Pattern cannot be empty.";
    }

    if (pattern.length() > 10)
    {
        return "Warning: Pattern is very long. This may take a very long time to find!";
    }

    if (!isValidBase58(pattern))
    {
        return "Error: Pattern contains invalid characters. Only use Base58 characters:\n"
               "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    }

    if (hasAmbiguousChars(pattern))
    {
        return "Warning: Pattern contains ambiguous characters (0, O, I, l).\n"
               "These characters are excluded from Base58 to avoid confusion.\n"
               "Your pattern may be harder to read than intended.";
    }

    return "";
}

/* Worker function for vanity wallet generation */
VanityResult vanityWorker(
    const std::string pattern,
    const bool searchAtStart,
    std::atomic<uint64_t> &attemptCounter,
    const std::atomic<bool> &cancelFlag,
    const bool debugMode,
    std::string &latestAddress,
    std::mutex &addressMutex)
{
    VanityResult result;
    result.found = false;
    result.attempts = 0;

    Crypto::PublicKey publicKey;
    Crypto::SecretKey secretKey;

    /* Generate address from private key */
    while (!cancelFlag.load())
    {
        /* Generate a new keypair */
        Crypto::generate_keys(publicKey, secretKey);

        /* Generate address from public key */
        Pastella::AccountPublicAddress address;
        address.publicKey = publicKey;

        std::string addressStr = Utilities::getAccountAddressAsStr(
            Pastella::parameters::PASTELLA_PUBLIC_ADDRESS_BASE58_PREFIX,
            address);

        /* Update latest address for debug mode */
        if (debugMode)
        {
            std::lock_guard<std::mutex> lock(addressMutex);
            latestAddress = addressStr;
        }

        /* Check if pattern matches */
        if (addressStr.length() >= 4)
        {
            std::string searchArea = addressStr.substr(4);

            bool match = searchAtStart
                ? searchArea.compare(0, pattern.length(), pattern) == 0
                : searchArea.length() >= pattern.length() &&
                  searchArea.compare(searchArea.length() - pattern.length(), pattern.length(), pattern) == 0;

            if (match)
            {
                result.found = true;
                result.publicKey = publicKey;
                result.secretKey = secretKey;
                result.address = addressStr;
                result.attempts = attemptCounter.fetch_add(1) + 1;
                return result;
            }
        }

        /* Increment attempt counter */
        attemptCounter.fetch_add(1);
        result.attempts++;
    }

    return result;
}

/* Main vanity wallet creation function */
std::shared_ptr<WalletBackend> createVanityWallet(const ZedConfig &config)
{
    std::cout << InformationMsg("\n═════════════════════════════════════════════════════════════\n");
    std::cout << InformationMsg("║                    VANITY WALLET GENERATOR                  ║\n");
    std::cout << InformationMsg("═════════════════════════════════════════════════════════════\n\n");

    /* Get pattern from user */
    std::string pattern;
    while (true)
    {
        std::string prompt = "Enter the pattern to search for (after '" + std::string(WalletConfig::addressPrefix) + "' prefix): ";
        std::cout << InformationMsg(prompt);
        std::getline(std::cin, pattern);

        Utilities::trim(pattern);

        std::string checkResult = checkPattern(pattern);

        if (checkResult.empty())
        {
            break;
        }

        /* If it's an error, continue loop. If it's a warning, confirm */
        if (checkResult.find("Error:") == 0)
        {
            std::cout << WarningMsg(checkResult) << "\n\n";
        }
        else if (checkResult.find("Warning:") == 0)
        {
            std::cout << WarningMsg(checkResult) << "\n";
            std::cout << InformationMsg("Use this pattern anyway? (y/n): ");

            std::string confirm;
            std::getline(std::cin, confirm);
            Utilities::trim(confirm);

            if (confirm == "y" || confirm == "Y")
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    /* Get search position */
    bool searchAtStart = true;
    while (true)
    {
        std::string positionPrompt = "\nSearch at [B]eginning or [E]nd of address (after " + std::string(WalletConfig::addressPrefix) + ")? ";
        std::cout << InformationMsg(positionPrompt);
        std::string position;
        std::getline(std::cin, position);
        Utilities::trim(position);

        if (position == "B" || position == "b")
        {
            searchAtStart = true;
            break;
        }
        else if (position == "E" || position == "e")
        {
            searchAtStart = false;
            break;
        }
        else
        {
            std::cout << WarningMsg("Invalid choice. Please enter B or E.") << "\n";
        }
    }

    /* Get thread count */
    unsigned int numThreads = std::thread::hardware_concurrency();
    while (true)
    {
        std::cout << InformationMsg("\nEnter number of threads [1-16, default=")
                  << InformationMsg(std::to_string(numThreads))
                  << InformationMsg("]: ");

        std::string threadInput;
        std::getline(std::cin, threadInput);
        Utilities::trim(threadInput);

        if (threadInput.empty())
        {
            /* Use default */
            break;
        }

        try
        {
            int threads = std::stoi(threadInput);

            if (threads < 1 || threads > 16)
            {
                std::cout << WarningMsg("Thread count must be between 1 and 16.") << "\n";
            }
            else
            {
                numThreads = static_cast<unsigned int>(threads);
                break;
            }
        }
        catch (...)
        {
            std::cout << WarningMsg("Invalid number. Please enter a value between 1 and 16.") << "\n";
        }
    }

    /* Display search info */
    std::cout << "\n";
    std::cout << InformationMsg("Pattern: ") << SuccessMsg(pattern) << "\n";
    std::cout << InformationMsg("Position: ") << SuccessMsg(searchAtStart ? "Beginning" : "End") << "\n";
    std::cout << InformationMsg("Threads: ") << SuccessMsg(std::to_string(numThreads)) << "\n";

    const std::string searchDesc = searchAtStart
        ? std::string(WalletConfig::addressPrefix) + "Q" + pattern + "..."
        : "..." + std::string(WalletConfig::addressPrefix) + "Q..." + pattern;

    std::cout << InformationMsg("\nSearching for addresses ") << SuccessMsg(searchDesc) << "\n";
    std::cout << InformationMsg("Press Q to cancel...\n\n");

    /* Atomic counters */
    std::atomic<uint64_t> totalAttempts(0);
    std::atomic<bool> foundMatch(false);
    std::atomic<bool> workerCancel(false);
    std::atomic<bool> userCancel(false);

#ifndef _WIN32
    /* Set terminal to non-canonical mode for instant key detection */
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#endif

    /* Launch worker threads */
    std::vector<std::thread> workers;
    std::vector<VanityResult> results(numThreads);

    auto startTime = std::chrono::steady_clock::now();

    for (unsigned int i = 0; i < numThreads; i++)
    {
        workers.emplace_back([&, i]()
        {
            /* Dummy variables for debug mode (disabled) */
            std::string latestAddress;
            std::mutex addressMutex;

            results[i] = vanityWorker(pattern, searchAtStart, totalAttempts, workerCancel,
                                      false, latestAddress, addressMutex);
        });
    }

    /* Launch input thread for cancellation */
    std::thread inputThread([&]()
    {
#ifndef _WIN32
        char c;
        while (!foundMatch.load() && !workerCancel.load())
        {
            /* Use poll with timeout instead of blocking read */
            struct pollfd pfd;
            pfd.fd = STDIN_FILENO;
            pfd.events = POLLIN;

            int pollResult = poll(&pfd, 1, 100); /* 100ms timeout */

            if (pollResult > 0 && (pfd.revents & POLLIN))
            {
                if (read(STDIN_FILENO, &c, 1) > 0)
                {
                    if (c == 'q' || c == 'Q')
                    {
                        userCancel.store(true);
                        workerCancel.store(true);
                        g_cancelFlag.store(true);
                        break;
                    }
                }
            }
        }
#else
        /* Windows: use _kbhit() for non-blocking input detection */
        while (!foundMatch.load() && !workerCancel.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (_kbhit())
            {
                int c = _getch();
                if (c == 'q' || c == 'Q')
                {
                    userCancel.store(true);
                    workerCancel.store(true);
                    g_cancelFlag.store(true);
                    break;
                }
            }
        }
#endif
    });

    /* Progress reporting thread */
    std::thread progressThread([&]()
    {
        while (!foundMatch.load() && !workerCancel.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            uint64_t attempts = totalAttempts.load();

            auto currentTime = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                currentTime - startTime).count();

            double attemptsPerSec = elapsed > 0 ? static_cast<double>(attempts) / elapsed : 0.0;

            std::cout << "\r[Stats: " << InformationMsg(formatNumber(attempts))
                      << " attempts, " << InformationMsg(formatNumber(static_cast<uint64_t>(attemptsPerSec)))
                      << " attempts/sec, " << InformationMsg(std::to_string(elapsed) + "s")
                      << InformationMsg(" elapsed]") << "    " << std::flush;
        }
    });

    /* Wait for results */
    VanityResult finalResult;
    finalResult.found = false;

    for (unsigned int i = 0; i < numThreads; i++)
    {
        workers[i].join();

        if (results[i].found && !finalResult.found)
        {
            finalResult = results[i];
            foundMatch.store(true);
            workerCancel.store(true);

            /* Cancel other workers immediately when match found */
            g_cancelFlag.store(true);

            /* Give threads time to exit */
            std::this_thread::sleep_for(std::chrono::milliseconds(250));

            /* Stop threads */
            inputThread.join();
            progressThread.join();

#ifndef _WIN32
            /* Restore terminal IMMEDIATELY */
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

            /* Drain any pending input */
            int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
            fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
            char buf[1024];
            while (read(STDIN_FILENO, buf, sizeof(buf)) > 0);
            fcntl(STDIN_FILENO, F_SETFL, flags);
#endif

            /* Print separator and flush */
            std::cout << "\r" << std::flush;
            std::cout << "\n\n" << std::flush;

            /* Small delay to ensure terminal is ready */
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            break;
        }
    }

    /* Restore terminal settings if not already done (e.g., user cancelled) */
    if (!finalResult.found)
    {
#ifndef _WIN32
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

        /* Stop threads */
        if (inputThread.joinable())
        {
            inputThread.join();
        }
        if (progressThread.joinable())
        {
            progressThread.join();
        }
    }

    auto endTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        endTime - startTime).count();

    std::cout << "\n";

    /* Check if cancelled */
    if (userCancel.load() || !finalResult.found)
    {
        std::cout << WarningMsg("Search cancelled.") << "\n";
        std::cout << InformationMsg("Total attempts: ") << InformationMsg(formatNumber(totalAttempts.load())) << "\n";
        return nullptr;
    }

    /* Display result */
    std::cout << SuccessMsg("Found match!") << "\n";
    std::cout << InformationMsg("Address: ") << SuccessMsg(finalResult.address) << "\n";
    std::cout << InformationMsg("Public Key: ") << SuccessMsg(Common::podToHex(finalResult.publicKey)) << "\n";
    std::cout << InformationMsg("Private Key: ") << SuccessMsg(Common::podToHex(finalResult.secretKey)) << "\n";
    std::cout << InformationMsg("Total attempts: ") << InformationMsg(formatNumber(finalResult.attempts)) << "\n";
    std::cout << InformationMsg("Time elapsed: ") << InformationMsg(std::to_string(elapsed) + "s") << "\n";
    std::cout << InformationMsg("Average speed: ") << InformationMsg(formatNumber(
        static_cast<uint64_t>(elapsed > 0 ? finalResult.attempts / elapsed : 0))) << " attempts/sec\n\n";

    /* Save wallet */
    std::cout << InformationMsg("Saving wallet...\n");

    const std::string walletFileName = getNewWalletFileName();

    const std::string msg = "Give your new wallet a password: ";

    const bool verifyPassword = true;

    const std::string walletPass = getWalletPassword(verifyPassword, msg);

    const auto [error, walletBackend] = WalletBackend::importWalletFromKeys(
        finalResult.secretKey,
        walletFileName,
        walletPass,
        0, /* scanHeight */
        config.host,
        config.port,
        config.ssl,
        config.threads);

    if (error)
    {
        std::cout << WarningMsg("Failed to save wallet: " + error.getErrorMessage()) << "\n";
        return nullptr;
    }

    std::cout << SuccessMsg("\nWallet saved to: ") << SuccessMsg(walletFileName) << "\n\n";

    std::cout << WarningMsg("IMPORTANT: Backup your private key!") << "\n";
    std::cout << WarningMsg("Private Key: ") << SuccessMsg(Common::podToHex(finalResult.secretKey)) << "\n\n";

    return walletBackend;
}
