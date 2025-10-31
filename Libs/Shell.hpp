#pragma once

#ifndef SHELL_HPP
#define SHELL_HPP

#include "thirdparty.hpp"
#include "Credentials.hpp"
#include "CryptoUtils.hpp"

class Shell {
private:
    std::unordered_map<string, std::function<void()>> commandMap;
// Terminal state
    struct termios oldTerm;

    // Input/history
    std::vector<std::string> history;
    size_t historyIndex;

    // Session state
    bool running;
    bool loggedIn;
    std::string currentUser;

    std::vector<uint8_t> sessionMasterKey;

    // Internal helpers: terminal + I/O
    void enableRawMode();
    void disableRawMode();
    std::string editInput();
    void createProcess();

    // Commands - explicit return types
    void help();
    void signUp();
    void login();
    void logout();
    void createPassword();
    void listPasswords();
    void viewPassword();
    void deletePassword();
    void cmdExit();

    // Vault helpers (used from Shell.cpp)
/*     UserVault loadUserVault(const std::string& username);
    void saveUserVault(const UserVault& vault);
    std::string getUserVaultPath(const std::string& username);
 */
    // Session management
    void clearSession();

    // Encryption helpers (used in Shell.cpp)
/*     EncryptedPacket encryptPasswordEntry(const PasswordEntry& entry, const std::string& subkeyInfo);
    PasswordEntry decryptPasswordEntry(const EncryptedPacket& packet, const std::string& subkeyInfo);
 */
public:
    Shell();
    ~Shell();

    void run();
};

#endif