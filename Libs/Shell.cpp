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
}

Shell::~Shell() {
    CryptoGlobalInit init;

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
    // compute prompt string once per loop redraw
    auto promptStr = [&]() -> string {
        return (loggedIn ? "\x1b[1;32m" + currentUser + "@ArborKey>\x1b[0m " : "\x1b[1;32mArborKey>\x1b[0m ");
    };

    std::cout << promptStr() << std::flush;

    size_t cursorPos = 0;

    while (true) {
        uint8_t c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n == -1) return buffer;

        switch (c) {
            case 1: // Ctrl + A
                if (cursorPos > 0) {
                    cursorPos = 0;
                    // Redraw prompt + buffer and move terminal cursor to the start of buffer
                    std::cout << "\r" << promptStr() << "\033[K" << buffer << std::flush;
                    if (!buffer.empty()) {
                        // Move left by the full buffer length so cursor sits at buffer start
                        std::cout << "\033[" << buffer.size() << "D" << std::flush;
                    }
                }
                break;
            case 5: // Ctrl + E
                if (cursorPos < buffer.size()) {
                    cursorPos = buffer.size();
                    // Redraw prompt + buffer. After printing buffer the terminal cursor is at the end.
                    std::cout << "\r" << promptStr() << "\033[K" << buffer << std::flush;
                }
                break;
            case 3:  // Ctrl + C
                buffer.clear();
                // If the user was logged in, securely clear session secrets
                if (this->loggedIn) {
                    this->clearSession(); // wipes sessionMasterKey/sessionSubKey and clears currentUser
                    std::cout << "\r\nSession terminated. You are now logged out.\r\n";
                } else {
                    std::cout << "\r\nInterrupted.\r\n";
                }
                // return empty so caller redraws prompt and input loop continues
                raise(SIGINT);
                return "";
            case 12: // Ctrl+L
                std::cout << "\033[2J\033[H"; // clear screen
                std::cout << promptStr() << std::flush;
                // redraw buffer and move cursor to cursorPos
                if (!buffer.empty()) {
                    std::cout << buffer << std::flush;
                    size_t moves = buffer.size() - cursorPos;
                    if (moves > 0) std::cout << "\033[" << moves << "D" << std::flush;
                }
                break;
            case 127: // Backspace
                if (cursorPos > 0) {
                    // erase char before cursor
                    buffer.erase(buffer.begin() + (cursorPos - 1));
                    cursorPos--;
                    // redraw line and position cursor
                    std::cout << "\r" << promptStr() << "\033[K" << buffer << std::flush;
                    size_t moves = buffer.size() - cursorPos;
                    if (moves > 0) std::cout << "\033[" << moves << "D" << std::flush;
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
                            cursorPos = buffer.size();
                            
                            // Redraw the line
                            std::cout << "\r" << promptStr() << "\033[K" << buffer << std::flush;
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
                            cursorPos = buffer.size();

                            // Redraw the line
                            std::cout << "\r" << promptStr() << "\033[K" << buffer << std::flush;
                        }
                    } else if (seq[1] == 'D') { // LEFT Arrow
                        if (cursorPos > 0) {
                            cursorPos--;
                            // Move cursor left one position
                            std::cout << "\033[1D" << std::flush;
                        }
                    } else if (seq[1] == 'C') { // RIGHT Arrow
                        if (cursorPos < buffer.size()) {
                            cursorPos++;
                            // Move cursor right one position
                            std::cout << "\033[1C" << std::flush;
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
                    // insert at cursor position
                    buffer.insert(buffer.begin() + cursorPos, static_cast<char>(c));
                    cursorPos++;

                    // redraw whole line and move cursor if needed
                    std::cout << "\r" << promptStr() << "\033[K" << buffer << std::flush;
                    size_t moves = buffer.size() - cursorPos;
                    if (moves > 0) std::cout << "\033[" << moves << "D" << std::flush;
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

// signUp: create vault and automatically log user in
void Shell::signUp() {
    if (loggedIn) {
        std::cout << "\r\nPlease logout first before creating a new account.\r\n";
        return;
    }

    std::cout << "\r\n=== ArborKey Registration ===\r\n";

    disableRawMode();
    Credentials creds;
    enableRawMode();

    string username = creds.getUsername();
    string password = creds.getPassword();

    // Prepare MasterKey params
    MasterKey mk;
    mk.masterParams.iterations = 100000;
    mk.masterParams.keySize = 32;

    // Derive master key (may generate salt inside mk)
    std::vector<uint8_t> masterKey;
    try {
        masterKey = CryptoUtils::calculateMasterKey(password, mk);
    } catch (const std::exception& ex) {
        std::cerr << "Failed to derive master key: " << ex.what() << "\n";
        creds.clear();
        return;
    }

    // SubKey params + derive
    SubKey sk;
    sk.subParams.hashType = "SHA512";
    sk.subParams.keySize = 32;

    std::vector<uint8_t> subKey;
    try {
        subKey = CryptoUtils::calculateSubKey(masterKey, "derived sub key", sk);
    } catch (const std::exception &ex) {
        CryptoUtils::secureZero(masterKey.data(), masterKey.size());
        std::cerr << "Failed to calculate subkey: " << ex.what() << "\n";
        creds.clear();
        return;
    }

    // Build vault and save
    Vault v;
    v.id = CryptoUtils::genVaultId();
    v.username = username;
    v.mk = mk;
    v.sk = sk;
    v.entries.clear();

    try {
        CryptoUtils::toFile(v, "vault.json");
        std::cout << "Vault written to vault.json\n";
    } catch (const std::exception& ex) {
        CryptoUtils::secureZero(masterKey.data(), masterKey.size());
        CryptoUtils::secureZero(subKey.data(), subKey.size());
        std::cerr << "Error writing vault: " << ex.what() << "\n";
        creds.clear();
        return;
    }

    // session: keep master & sub keys for session (do not zero)
    this->sessionMasterKey = std::move(masterKey);
    this->sessionSubKey = std::move(subKey);
    this->loggedIn = true;
    this->currentUser = username;

    std::cout << "\r\nAccount created and logged in as " << username << "\r\n";

    creds.clear();
}

// login: derive masterKey, verify subkey, then rederive subkey and set session keys
void Shell::login() {
    if (loggedIn) {
        std::cout << "\r\nYou are already logged in as: " << currentUser << "\r\n";
        return;
    }

    std::cout << "\r\n=== ArborKey Login ===\r\n";

    disableRawMode();
    Credentials creds;
    enableRawMode();

    string username = creds.getUsername();
    string password = creds.getPassword();

    // Load vault from disk
    Vault v;
    try {
        v = CryptoUtils::fromFile("vault.json");
    } catch (const std::exception& ex) {
        std::cerr << "Failed to read vault: " << ex.what() << "\r\n";
        creds.clear();
        return;
    }

    if (username != v.username) {
        std::cout << "No vault for username: " << username << "\r\n";
        creds.clear();
        return;
    }

    // Derive master key using stored params in vault (salt present)
    std::vector<uint8_t> masterKey;
    try {
        masterKey = CryptoUtils::calculateMasterKey(password, v.mk); // uses existing salt
    } catch (const std::exception& ex) {
        std::cerr << "Key derivation failed: " << ex.what() << "\r\n";
        creds.clear();
        return;
    }

    // Verify sub-key authenticity
    bool ok = CryptoUtils::verifySubKey(masterKey, v.sk, "derived sub key");
    if (!ok) {
        std::cout << "Authentication failed: incorrect password or corrupt vault.\r\n";
        CryptoUtils::secureZero(masterKey.data(), masterKey.size());
        creds.clear();
        return;
    }

    // Re-derive raw subkey bytes for session (this also checks integrity again)
    std::vector<uint8_t> subKey = CryptoUtils::rederiveSubKey(masterKey, v.sk, "derived sub key");
    if (subKey.empty()) {
        std::cout << "Failed to rederive subkey.\r\n";
        CryptoUtils::secureZero(masterKey.data(), masterKey.size());
        creds.clear();
        return;
    }

    // Authentication success: set session keys (rely on clearSession on logout)
    this->sessionMasterKey = std::move(masterKey);
    this->sessionSubKey = std::move(subKey);
    this->loggedIn = true;
    this->currentUser = username;

    std::cout << "\r\nLogin successful! Welcome back, " << username << "!\r\n";
    std::cout << "You have " << v.entries.size() << " stored password(s).\r\n\r\n";

    creds.clear();
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

// createPassword: prompts for fields, encrypts using the session subkey, stores to vault.json
void Shell::createPassword() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }

    std::cout << "\r\n=== Store New Password ===\r\n";

    // Temporarily disable raw-mode to read user fields more easily
    disableRawMode();

    // Collect fields
    string service, url, description, plainPassword;
    std::cout << "Service name (e.g., Gmail, GitHub): ";
    std::getline(std::cin, service);
    std::cout << "URL: ";
    std::getline(std::cin, url);
    std::cout << "Description: ";
    std::getline(std::cin, description);

    // Read password without echo using termios
    {
        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        std::cout << "Password: " << std::flush;
        std::getline(std::cin, plainPassword);
        std::cout << "\n";

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }

    // Load vault
    Vault v;
    try {
        v = CryptoUtils::fromFile("vault.json");
    } catch (const std::exception& ex) {
        std::cerr << "Failed to read vault: " << ex.what() << "\r\n";
        // zero password
        if (!plainPassword.empty()) CryptoUtils::secureZero(&plainPassword[0], plainPassword.size());
        enableRawMode();
        return;
    }

    // determine next entry ID (uint32_t assumed)
    uint32_t nextId = 1;
    if (!v.entries.empty()) {
        // If Entry.id is numeric type, get highest + 1
        nextId = v.entries.back().id + 1;
    }

    // Build EncryptedPacket
    std::vector<uint8_t> plainVec(plainPassword.begin(), plainPassword.end());
    string aad = "{\"vault_id\":\"" + v.id + "\",\"entry_id\":\"" + std::to_string(nextId) + "\",\"user\":\"" + this->currentUser + "\"}";

    EncryptedPacket ep;
    try {
        ep = CryptoUtils::encryptData(plainVec, this->sessionSubKey, aad);
    } catch (const std::exception& ex) {
        std::cerr << "Encryption failed: " << ex.what() << "\r\n";
        CryptoUtils::secureZero(plainVec.data(), plainVec.size());
        if (!plainPassword.empty()) CryptoUtils::secureZero(&plainPassword[0], plainPassword.size());
        enableRawMode();
        return;
    }

    // Create entry and timestamp (ISO8601 UTC)
    Entry entry;
    entry.id = nextId;
    entry.title = service;
    entry.md.url = url;
    // timestamp
    {
        auto now = std::chrono::system_clock::now();
        std::time_t tnow = std::chrono::system_clock::to_time_t(now);
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&tnow));
        entry.md.timestamp = buf;
    }
    entry.ep = ep;

    // Append and save
    v.entries.push_back(std::move(entry));
    try {
        CryptoUtils::toFile(v, "vault.json");
        std::cout << "Entry stored successfully (id=" << nextId << ").\r\n";
    } catch (const std::exception& ex) {
        std::cerr << "Failed to write vault: " << ex.what() << "\r\n";
    }

    // zero sensitive buffers
    CryptoUtils::secureZero(plainVec.data(), plainVec.size());
    if (!plainPassword.empty()) CryptoUtils::secureZero(&plainPassword[0], plainPassword.size());

    enableRawMode();
}

// listPasswords: show minimal info about each entry (id, title, created)
void Shell::listPasswords() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }

    Vault v;
    try {
        v = CryptoUtils::fromFile("vault.json");
    } catch (const std::exception& ex) {
        std::cerr << "Failed to read vault: " << ex.what() << "\r\n";
        return;
    }

    if (v.entries.empty()) {
        std::cout << "\r\nNo entries stored.\r\n";
        return;
    }

    std::cout << "\r\nStored entries:\r\n";
    for (const auto &e : v.entries) {
        std::cout << "  ID: " << e.id
                  << "  Title: " << (e.title.empty()? "<no title>" : e.title)
                  << "  Created: " << (e.md.timestamp.empty() ? "<unknown>" : e.md.timestamp)
                  << "\r\n";
    }
    std::cout << "\r\n";
}

// viewPassword: decrypt and show password for a chosen entry id (wipes plaintext)
void Shell::viewPassword() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }

    disableRawMode();
    std::cout << "\r\nEnter entry ID to view: ";
    std::string sid;
    std::getline(std::cin, sid);
    enableRawMode();

    if (sid.empty()) {
        std::cout << "No id provided.\r\n";
        return;
    }

    // parse numeric id
    uint32_t id = 0;
    try {
        id = static_cast<uint32_t>(std::stoul(sid));
    } catch (...) {
        std::cout << "Invalid id.\r\n";
        return;
    }

    Vault v;
    try {
        v = CryptoUtils::fromFile("vault.json");
    } catch (const std::exception& ex) {
        std::cerr << "Failed to read vault: " << ex.what() << "\r\n";
        return;
    }

    auto it = std::find_if(v.entries.begin(), v.entries.end(), [&](const Entry &e){ return e.id == id; });
    if (it == v.entries.end()) {
        std::cout << "Entry not found: " << id << "\r\n";
        return;
    }

    // Decrypt the entry (returns raw bytes)
    std::vector<uint8_t> plain;
    try {
        plain = CryptoUtils::decryptData(it->ep, this->sessionSubKey);
    } catch (const std::exception &ex) {
        std::cerr << "Decryption failed: " << ex.what() << "\r\n";
        return;
    }

    // Show metadata and password (password is ephemeral)
    std::string password(plain.begin(), plain.end());
    std::cout << "\r\n== Entry " << id << " ==\r\n";
    std::cout << "Title: " << it->title << "\r\n";
    std::cout << "URL: " << it->md.url << "\r\n";
    std::cout << "Created: " << it->md.timestamp << "\r\n";
    std::cout << "Password: " << password << "\r\n\r\n";

    // wipe plaintext from memory
    if (!plain.empty()) CryptoUtils::secureZero(plain.data(), plain.size());
    CryptoUtils::secureZero(const_cast<char*>(password.data()), password.size());
}

// deletePassword: remove an entry by id and save
void Shell::deletePassword() {
    if (!loggedIn) {
        std::cout << "\r\nPlease login first.\r\n";
        return;
    }

    disableRawMode();
    std::cout << "\r\nEnter entry ID to delete: ";
    std::string sid;
    std::getline(std::cin, sid);
    if (sid.empty()) {
        enableRawMode();
        std::cout << "No id provided.\r\n";
        return;
    }

    uint32_t id = 0;
    try {
        id = static_cast<uint32_t>(std::stoul(sid));
    } catch (...) {
        enableRawMode();
        std::cout << "Invalid id.\r\n";
        return;
    }

    std::cout << "Type 'yes' to permanently delete entry " << id << ": ";
    std::string confirm;
    std::getline(std::cin, confirm);
    enableRawMode();

    if (confirm != "yes") {
        std::cout << "Delete cancelled.\r\n";
        return;
    }

    Vault v;
    try {
        v = CryptoUtils::fromFile("vault.json");
    } catch (const std::exception& ex) {
        std::cerr << "Failed to read vault: " << ex.what() << "\r\n";
        return;
    }

    auto it = std::remove_if(v.entries.begin(), v.entries.end(), [&](const Entry &e){ return e.id == id; });
    if (it == v.entries.end()) {
        std::cout << "Entry not found: " << id << "\r\n";
        return;
    }

    v.entries.erase(it, v.entries.end());

    try {
        CryptoUtils::toFile(v, "vault.json");
        std::cout << "Entry " << id << " deleted.\r\n";
    } catch (const std::exception& ex) {
        std::cerr << "Failed to write vault: " << ex.what() << "\r\n";
    }
}

// cmdExit: clean exit
void Shell::cmdExit() {
    std::cout << "\r\nExiting ArborKey...\r\n";
    this->clearSession();
    this->disableRawMode();
    this->running = false;
}

// -- clear session
void Shell::clearSession() {
    if (!this->sessionMasterKey.empty()) {
        CryptoUtils::secureZero(this->sessionMasterKey.data(), this->sessionMasterKey.size());
        this->sessionMasterKey.clear();
    }
    if (!this->sessionSubKey.empty()) {
        CryptoUtils::secureZero(this->sessionSubKey.data(), this->sessionSubKey.size());
        this->sessionSubKey.clear();
    }
    this->loggedIn = false;
    this->currentUser.clear();
}