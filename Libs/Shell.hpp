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
    std::vector<string> history;
    size_t historyIndex;

    // Session state
    bool running;
    bool loggedIn;
    string currentUser;

    std::vector<uint8_t> sessionMasterKey;
    std::vector<uint8_t> sessionSubKey;

    // Internal helpers: terminal + I/O
    void enableRawMode();
    void disableRawMode();
    string editInput();
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
    void clearSession();

public:
    Shell();
    ~Shell();

    void run();
};

#endif