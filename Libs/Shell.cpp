#include "Shell.hpp"

Shell::Shell() : historyIndex(0), running(false), loggedIn(false) {
    if (tcgetattr(STDIN_FILENO, &this->oldTerm) == -1) std::runtime_error("Failed tcsetattr()");
    this->commandMap = {
        {"help",    [this]() { this->help(); }},
        {"signup",  [this]() { this->signUp(); }},
        {"login",   [this]() { this->login(); }},
        {"logout",  [this]() { this->logout(); }},
        {"create",  [this]() { this->createPassword(); }},
        {"list",    [this]() { this->listPasswords(); }},
        {"view",    [this]() { this->viewPassword(); }},
        {"delete",  [this]() { this->deletePassword(); }},
        {"exit",    [this]() { this->cmdExit(); }}
    };

    // Ensure vault directory exists
    fs::create_directories("vaults");
}

Shell::~Shell() {
    this->disableRawMode();
    this->clearSession();
}

void Shell::run() {
    std::cout << "\033[2J\033[H"; // clear screen
    std::cout << "=== ArborKey Password Manager ===\n";
    std::cout << "Type 'help' for available commands\n\n";

    this->enableRawMode();
    string input;
    this->running = true;

    while (this->running) {
        input = editInput();

        // Don't do anything if the user just pressed enter
        if (input.empty()) {
            continue;
        }
        
        auto it = this->commandMap.find(input);

        if (it != this->commandMap.end()) {
            // We found the command!
            // 'it->second' is the std::function<void()>
            // Call the function stored in the map:
            it->second(); 
        } else {
            // We didn't find the command
            std::cout << "Unknown command: " << input << "\r\n" << std::flush;
        }
    }
}

void Shell::enableRawMode() {
    // reference: https://blog.mbedded.ninja/programming/operating-systems/linux/linux-serial-ports-using-c-cpp/
    struct termios newTerm = this->oldTerm; // start from current settings
    // Turn off s/w flow ctrl | disables parity checking | Disable any special handling of received bytes
    newTerm.c_iflag &= ~(IXON|IXOFF|IXANY| INPCK |IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL);   
    // Prevent special interpretation of output bytes (e.g. newline chars) | Prevent conversion of newline to carriage return/line feed
    newTerm.c_oflag &= ~(OPOST | ONLCR);  
    newTerm.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
    newTerm.c_cc[VMIN] = 1;
    newTerm.c_cc[VTIME] = 0; // no timeout
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &newTerm);

}

void Shell::disableRawMode() {
    if (tcsetattr(STDIN_FILENO, TCSANOW, &this->oldTerm) == -1) std::runtime_error("Failed to restore terminal");
}

// reference: https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fd3i71xaburhd42.cloudfront.net%2Fd0017b356aaf4c59fe734490a778d8f5ec98287a%2F4-Table3-1.png&f=1&nofb=1&ipt=f87087e3707bd4a06b28eb19545d6d8b9b76e2f4dda633b0210a1d674161c266
// reference: https://www.geeksforgeeks.org/cpp/signal-handling-in-cpp/
string Shell::editInput() {
    string buffer;
    this->historyIndex = this->history.size();
    
    string inProgressBuffer = ""; 
    std::cout << (loggedIn ? "\x1b[1;32m" + currentUser + "@ArborKey>\x1b[0m " : "\x1b[1;32mArborKey>\x1b[0m ") << std::flush;

    while (true) {
        uint8_t c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n == -1) return buffer;

        switch (c) {
            case 3:  // Ctrl + C
                raise(SIGINT);
                buffer.clear();
                return "";
            case 12: // Ctrl+L
                std::cout << "\033[2J\033[H"; // clear screen
                std::cout << (loggedIn ? "\x1b[1;32m" + currentUser + "@ArborKey>\x1b[0m " : "\x1b[1;32mArborKey>\x1b[0m ") << std::flush;
                break;
            case 127: // Backspace
                if (!buffer.empty()) {
                    buffer.pop_back();
                    std::cout << "\b \b" << std::flush;
                }
                break;
            // --- HANDLE ARROW KEYS ---
            case 27: { // ESC - Start of arrow key sequence
                char seq[2];
                // Read the next two chars
                if (read(STDIN_FILENO, &seq[0], 1) == -1) break;
                if (read(STDIN_FILENO, &seq[1], 1) == -1) break;

                if (seq[0] == '[') {
                    if (seq[1] == 'A') { // UP Arrow
                        if (!this->history.empty() && this->historyIndex > 0) {
                            if (this->historyIndex == this->history.size()) {
                                // Save the current (new) buffer
                                inProgressBuffer = buffer;
                            }
                            this->historyIndex--;
                            buffer = this->history[this->historyIndex];
                            
                            // Redraw the line
                            std::cout << "\r" << (loggedIn ? "\x1b[1;32m" + currentUser + "@ArborKey>\x1b[0m " : "\x1b[1;32mArborKey>\x1b[0m ")
                                      << "\033[K" << buffer << std::flush;
                        }
                    } else if (seq[1] == 'B') { // DOWN Arrow
                        if (this->historyIndex < this->history.size()) {
                            this->historyIndex++;
                            if (this->historyIndex == this->history.size()) {
                                // Reached the bottom, restore the new buffer
                                buffer = inProgressBuffer;
                            } else {
                                // Still in history, get the next one
                                buffer = this->history[this->historyIndex];
                            }

                            // Redraw the line
                            std::cout << "\r" << (loggedIn ? "\x1b[1;32m" + currentUser + "@ArborKey>\x1b[0m " : "\x1b[1;32mArborKey>\x1b[0m ")
                                      << "\033[K" << buffer << std::flush;
                        }
                    }
                }
                break;
            }

            case '\r': // Carriage Return
            case '\n': // Line Feed (Enter)
                std::cout << "\r\n" << std::flush; 
                if (!buffer.empty()) {
                    this->history.push_back(buffer);
                }
                return buffer;
            default:
                // Only echo and add printable characters
                if (std::isprint(c)) {
                    buffer.push_back(c);
                    std::cout << c << std::flush;
                }
        }
    
    }
}

void Shell::help() {
    std::cout << "\r\nAvailable commands:\r\n";
    std::cout << "  signup  - Create a new user account\r\n";
    std::cout << "  login   - Log into your account\r\n";
    std::cout << "  logout  - Log out of your account\r\n";
    std::cout << "  create  - Store a new password\r\n";
    std::cout << "  list    - List all stored passwords\r\n";
    std::cout << "  view    - View a specific password\r\n";
    std::cout << "  delete  - Delete a stored password\r\n";
    std::cout << "  help    - Show this help message\r\n";
    std::cout << "  exit    - Exit ArborKey\r\n\r\n";
}

void Shell::signUp() {
    if (loggedIn) {
        std::cout << "\r\nPlease logout first before creating a new account.\r\n";
        return;
    }
    
    std::cout << "\r\n=== ArborKey Registration ===\r\n";
    
    // Temporarily disable raw mode for credential input
    disableRawMode();
    Credentials creds;
    enableRawMode();
    
    string username = creds.getUsername();
    string password = creds.getPassword();
    
    // Check if user already exists
    if (fs::exists(getUserVaultPath(username))) {
        std::cout << "\r\nUser already exists!\r\n";
        creds.clear();
        return;
    }
    
    std::cout << "\r\nCreating your secure vault...\r\n";
    
    // Generate PBKDF2 parameters
    PbkdfParams pbkdfParams;
    pbkdfParams.salt = CryptoUtils::genSalt(32);
    pbkdfParams.iterations = 100000; // Strong iteration count
    pbkdfParams.keySize = 64; // 512-bit master key
    
    // Derive master key from password
    std::vector<uint8_t> masterKey = CryptoUtils::deriveKeyFromPassword(password, pbkdfParams);
    
    // Generate signing key pair for the user
    auto signKeyPair = CryptoUtils::genSignKeyPair();
    auto signPubKey = CryptoUtils::exportSignPublicKey(*signKeyPair);
    
    // Export private signing key (we need to store it encrypted)
    std::vector<uint8_t> signPrivKeyBytes(ED25519_KEY_SIZE);
    word32 privKeySize = (word32)signPrivKeyBytes.size();
    if (wc_ed25519_export_private_only(&signKeyPair->key, signPrivKeyBytes.data(), &privKeySize) != 0) {
        std::cout << "\r\nFailed to export signing key\r\n";
        CryptoUtils::secureZero(masterKey.data(), masterKey.size());
        creds.clear();
        return;
    }
    signPrivKeyBytes.resize(privKeySize);
    
    // Derive sub-key for encrypting the signing key
    std::vector<uint8_t> signKeyEncKey = CryptoUtils::subKey(masterKey, "user-signing-key-encryption", 32);
    
    // Encrypt the private signing key
    MetaData signKeyMeta("User signing key");
    EncryptedPacket encryptedSignKey = CryptoUtils::encryptData(signPrivKeyBytes, signKeyEncKey, signKeyMeta);
    
    // Create master key hash for verification
    std::vector<uint8_t> masterKeyHash = CryptoUtils::calculateHash(masterKey);
    
    // Create user vault
    UserVault vault;
    vault.username = username;
    vault.masterKeyHash = masterKeyHash;
    vault.signPublicKey = signPubKey;
    vault.pbkdfParams = pbkdfParams;
    vault.encryptedSignKey = std::move(encryptedSignKey);
    
    // Save vault
    saveUserVault(vault);
    
    std::cout << "\r\nAccount created successfully!\r\n";
    std::cout << "Username: " << username << "\r\n";
    std::cout << "You can now login with your credentials.\r\n\r\n";
    
    // Secure cleanup
    CryptoUtils::secureZero(masterKey.data(), masterKey.size());
    CryptoUtils::secureZero(signKeyEncKey.data(), signKeyEncKey.size());
    CryptoUtils::secureZero(signPrivKeyBytes.data(), signPrivKeyBytes.size());
    creds.clear();
}

void Shell::login() {
    if (loggedIn) {
        std::cout << "\r\nYou are already logged in as: " << currentUser << "\r\n";
        return;
    }
    
    std::cout << "\r\n=== ArborKey Login ===\r\n";
    
    // Temporarily disable raw mode for credential input
    disableRawMode();
    Credentials creds;
    enableRawMode();
    
    string username = creds.getUsername();
    string password = creds.getPassword();
    
    try {
        // Load user vault
        UserVault vault = loadUserVault(username);
        
        // Derive master key from password
        std::vector<uint8_t> masterKey = CryptoUtils::deriveKeyFromPassword(password, vault.pbkdfParams);
        
        // Verify master key
        std::vector<uint8_t> computedHash = CryptoUtils::calculateHash(masterKey);
        if (!CryptoUtils::verifyHash(computedHash, vault.masterKeyHash)) {
            std::cout << "\r\nInvalid password!\r\n";
            CryptoUtils::secureZero(masterKey.data(), masterKey.size());
            creds.clear();
            return;
        }
        
        // Decrypt signing key
        std::vector<uint8_t> signKeyEncKey = CryptoUtils::subKey(masterKey, "user-signing-key-encryption", 32);
        std::vector<uint8_t> signPrivKeyBytes = CryptoUtils::decryptData(vault.encryptedSignKey, signKeyEncKey);
        
        // Import signing key
        sessionSignKey = std::make_unique<EcKeyPair>();
        if (wc_ed25519_import_private_only(signPrivKeyBytes.data(), (word32)signPrivKeyBytes.size(), &sessionSignKey->key) != 0) {
            std::cout << "\r\nFailed to load signing key\r\n";
            CryptoUtils::secureZero(masterKey.data(), masterKey.size());
            CryptoUtils::secureZero(signKeyEncKey.data(), signKeyEncKey.size());
            CryptoUtils::secureZero(signPrivKeyBytes.data(), signPrivKeyBytes.size());
            creds.clear();
            return;
        }
        
        // Import public key as well
        if (wc_ed25519_import_public(vault.signPublicKey.data(), (word32)vault.signPublicKey.size(), &sessionSignKey->key) != 0) {
            std::cout << "\r\nFailed to load public signing key\r\n";
            CryptoUtils::secureZero(masterKey.data(), masterKey.size());
            CryptoUtils::secureZero(signKeyEncKey.data(), signKeyEncKey.size());
            CryptoUtils::secureZero(signPrivKeyBytes.data(), signPrivKeyBytes.size());
            creds.clear();
            return;
        }
        
        // Set session variables
        loggedIn = true;
        currentUser = username;
        sessionMasterKey = masterKey;
        
        std::cout << "\r\nLogin successful! Welcome back, " << username << "!\r\n";
        std::cout << "You have " << vault.storedPasswords.size() << " stored password(s).\r\n\r\n";
        
        // Secure cleanup
        CryptoUtils::secureZero(signKeyEncKey.data(), signKeyEncKey.size());
        CryptoUtils::secureZero(signPrivKeyBytes.data(), signPrivKeyBytes.size());
        creds.clear();
        
    } catch (const std::exception& e) {
        std::cout << "\r\nLogin failed: " << e.what() << "\r\n";
        creds.clear();
    }
}

void Shell::logout() {
    if (!loggedIn) {
        std::cout << "\r\nYou are not logged in.\r\n";
        return;
    }
    
    std::cout << "\r\nLogging out...\r\n";
    clearSession();
    std::cout << "Logged out successfully.\r\n\r\n";
}

void Shell::createPassword() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }
    
    std::cout << "\r\n=== Store New Password ===\r\n";
    
    disableRawMode();
    
    PasswordEntry entry;
    
    std::cout << "Service name (e.g., Gmail, GitHub): ";
    std::getline(std::cin, entry.serviceName);
    
    std::cout << "Username/Email: ";
    std::getline(std::cin, entry.username);
    
    std::cout << "Password: ";
    // Read password hidden
    struct termios oldTerm, newTerm;
    tcgetattr(STDIN_FILENO, &oldTerm);
    newTerm = oldTerm;
    newTerm.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newTerm);
    std::getline(std::cin, entry.password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);
    std::cout << std::endl;
    
    std::cout << "Notes (optional): ";
    std::getline(std::cin, entry.notes);
    
    // Add timestamp
    char buf[sizeof("YYYY-MM-DDTHH:MM:SSZ")];
    std::time_t now = std::time(nullptr);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
    entry.timestamp = buf;
    
    enableRawMode();
    
    try {
        // Generate unique subkey for this password entry
        string subkeyInfo = "password-entry:" + entry.serviceName + ":" + entry.timestamp;
        EncryptedPacket encryptedEntry = encryptPasswordEntry(entry, subkeyInfo);
        
        // Load vault, add entry, save
        UserVault vault = loadUserVault(currentUser);
        vault.storedPasswords.push_back(std::move(encryptedEntry));
        saveUserVault(vault);
        
        std::cout << "\r\nPassword stored successfully!\r\n\r\n";
        
    } catch (const std::exception& e) {
        std::cout << "\r\nFailed to store password: " << e.what() << "\r\n";
    }
    
    // Clear sensitive data
    CryptoUtils::secureZero(&entry.password[0], entry.password.size());
}

void Shell::listPasswords() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }
    
    try {
        UserVault vault = loadUserVault(currentUser);
        
        if (vault.storedPasswords.empty()) {
            std::cout << "\r\nNo passwords stored yet.\r\n\r\n";
            return;
        }
        
        std::cout << "\r\n=== Stored Passwords ===\r\n";
        std::cout << "Index | Service Name | Username | Timestamp\r\n";
        std::cout << "------|--------------|----------|----------\r\n";
        
        for (size_t i = 0; i < vault.storedPasswords.size(); i++) {
            const auto& packet = vault.storedPasswords[i];
            std::cout << std::setw(5) << i << " | "
                      << packet.metadata.description.substr(0, 12) << " | ";
            
            // Try to decrypt just to show username (in real app, might want to cache metadata)
            try {
                string subkeyInfo = "password-entry:" + packet.metadata.description + ":" + packet.metadata.timestamp;
                PasswordEntry entry = decryptPasswordEntry(packet, subkeyInfo);
                std::cout << entry.username.substr(0, 8) << " | " << entry.timestamp << "\r\n";
            } catch (...) {
                std::cout << "[encrypted] | " << packet.metadata.timestamp << "\r\n";
            }
        }
        std::cout << "\r\n";
        
    } catch (const std::exception& e) {
        std::cout << "\r\nFailed to list passwords: " << e.what() << "\r\n";
    }
}

void Shell::viewPassword() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }
    
    disableRawMode();
    std::cout << "\r\nEnter password index: ";
    string indexStr;
    std::getline(std::cin, indexStr);
    enableRawMode();
    
    try {
        size_t index = std::stoul(indexStr);
        UserVault vault = loadUserVault(currentUser);
        
        if (index >= vault.storedPasswords.size()) {
            std::cout << "\r\nInvalid index.\r\n";
            return;
        }
        
        const auto& packet = vault.storedPasswords[index];
        string subkeyInfo = "password-entry:" + packet.metadata.description + ":" + packet.metadata.timestamp;
        PasswordEntry entry = decryptPasswordEntry(packet, subkeyInfo);
        
        std::cout << "\r\n=== Password Details ===\r\n";
        std::cout << "Service:   " << entry.serviceName << "\r\n";
        std::cout << "Username:  " << entry.username << "\r\n";
        std::cout << "Password:  " << entry.password << "\r\n";
        std::cout << "Notes:     " << entry.notes << "\r\n";
        std::cout << "Created:   " << entry.timestamp << "\r\n\r\n";
        
        // Clear sensitive data
        CryptoUtils::secureZero(&entry.password[0], entry.password.size());
        
    } catch (const std::exception& e) {
        std::cout << "\r\nFailed to view password: " << e.what() << "\r\n";
    }
}

void Shell::deletePassword() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }
    
    disableRawMode();
    std::cout << "\r\nEnter password index to delete: ";
    string indexStr;
    std::getline(std::cin, indexStr);
    enableRawMode();
    
    try {
        size_t index = std::stoul(indexStr);
        UserVault vault = loadUserVault(currentUser);
        
        if (index >= vault.storedPasswords.size()) {
            std::cout << "\r\nInvalid index.\r\n";
            return;
        }
        
        // Remove the entry
        vault.storedPasswords.erase(vault.storedPasswords.begin() + index);
        saveUserVault(vault);
        
        std::cout << "\r\nPassword deleted successfully.\r\n\r\n";
        
    } catch (const std::exception& e) {
        std::cout << "\r\nFailed to delete password: " << e.what() << "\r\n";
    }
}

void Shell::cmdExit() {
    std::cout << "\r\nExiting ArborKey...\r\n";
    if (loggedIn) {
        clearSession();
    }
    this->running = false;
}

// Helper functions

UserVault Shell::loadUserVault(const string& username) {
    string path = getUserVaultPath(username);
    
    if (!fs::exists(path)) {
        throw std::runtime_error("User vault not found");
    }
    
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open vault file");
    }
    
    json vaultJson;
    file >> vaultJson;
    file.close();
    
    return vaultJson.get<UserVault>();
}

void Shell::saveUserVault(const UserVault& vault) {
    string path = getUserVaultPath(vault.username);
    json vaultJson = vault;
    
    std::ofstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to save vault file");
    }
    
    file << vaultJson.dump(2);
    file.close();
}

string Shell::getUserVaultPath(const string& username) {
    return "vaults/" + username + ".vault.json";
}

void Shell::clearSession() {
    loggedIn = false;
    currentUser.clear();
    
    if (!sessionMasterKey.empty()) {
        CryptoUtils::secureZero(sessionMasterKey.data(), sessionMasterKey.size());
        sessionMasterKey.clear();
    }
    
    sessionSignKey.reset();
}

EncryptedPacket Shell::encryptPasswordEntry(const PasswordEntry& entry, const string& subkeyInfo) {
    // Serialize password entry to JSON
    json entryJson = entry;
    string entryStr = entryJson.dump();
    std::vector<uint8_t> entryBytes(entryStr.begin(), entryStr.end());
    
    // Derive unique sub-key for this entry
    std::vector<uint8_t> entryKey = CryptoUtils::subKey(sessionMasterKey, subkeyInfo, 32);
    
    // Create metadata
    MetaData meta(entry.serviceName);
    
    // Encrypt the entry
    EncryptedPacket packet = CryptoUtils::encryptData(entryBytes, entryKey, meta);
    
    // Sign the encrypted data
    std::vector<uint8_t> dataToSign;
    string metaStr = json(meta).dump();
    dataToSign.insert(dataToSign.end(), metaStr.begin(), metaStr.end());
    dataToSign.insert(dataToSign.end(), packet.cipherText.begin(), packet.cipherText.end());
    
    std::vector<uint8_t> dataHash = CryptoUtils::calculateHash(dataToSign);
    std::vector<uint8_t> signature = CryptoUtils::genSignature(dataHash, *sessionSignKey);
    
    // Store signature in AAD (Alternative: could add signature field to EncryptedPacket)
    packet.aesParams.aad.insert(packet.aesParams.aad.end(), signature.begin(), signature.end());
    
    // Clean up
    CryptoUtils::secureZero(entryKey.data(), entryKey.size());
    CryptoUtils::secureZero(entryBytes.data(), entryBytes.size());
    CryptoUtils::secureZero(dataToSign.data(), dataToSign.size());
    CryptoUtils::secureZero(dataHash.data(), dataHash.size());
    
    return packet;
}

PasswordEntry Shell::decryptPasswordEntry(const EncryptedPacket& packet, const string& subkeyInfo) {
    // Derive the sub-key
    std::vector<uint8_t> entryKey = CryptoUtils::subKey(sessionMasterKey, subkeyInfo, 32);
    
    // Decrypt the data
    std::vector<uint8_t> decryptedBytes = CryptoUtils::decryptData(packet, entryKey);
    
    // Parse JSON
    string decryptedStr(decryptedBytes.begin(), decryptedBytes.end());
    json entryJson = json::parse(decryptedStr);
    PasswordEntry entry = entryJson.get<PasswordEntry>();
    
    // Clean up
    CryptoUtils::secureZero(entryKey.data(), entryKey.size());
    CryptoUtils::secureZero(decryptedBytes.data(), decryptedBytes.size());
    
    return entry;
}