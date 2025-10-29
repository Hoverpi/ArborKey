#include "Credentials.hpp"
#include <termios.h>
#include <unistd.h>

// Helper: Read password without echo
static string readPasswordHidden() {
    struct termios oldTerm, newTerm;
    
    // Get current terminal settings
    if (tcgetattr(STDIN_FILENO, &oldTerm) == -1) {
        throw std::runtime_error("Failed to get terminal attributes");
    }
    
    // Disable echo
    newTerm = oldTerm;
    newTerm.c_lflag &= ~ECHO;
    
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) == -1) {
        throw std::runtime_error("Failed to set terminal attributes");
    }
    
    // Read password
    string password;
    std::getline(std::cin, password);
    
    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);
    
    // Print newline since echo was disabled
    std::cout << std::endl;
    
    return password;
}

// Constructor: ask interactively for username and password
Credentials::Credentials() {
    string userInput;
    string passInput;

    std::cout << "Enter username: ";
    std::getline(std::cin, userInput);

    std::cout << "Enter password: ";
    passInput = readPasswordHidden();

    // Validate input
    if (userInput.empty()) {
        throw std::invalid_argument("Username cannot be empty");
    }
    
    if (passInput.empty()) {
        throw std::invalid_argument("Password cannot be empty");
    }

    // Move into secure byte containers
    username.assign(userInput.begin(), userInput.end());
    password.assign(passInput.begin(), passInput.end());

    // Clear stack buffers to prevent password leakage
    if (!userInput.empty()) {
        CryptoUtils::secureZero(&userInput[0], userInput.size());
    }
    if (!passInput.empty()) {
        CryptoUtils::secureZero(&passInput[0], passInput.size());
    }
}

// Constructor: with provided values
Credentials::Credentials(const string& user, const string& pass) {
    if (user.empty()) {
        throw std::invalid_argument("Username cannot be empty");
    }
    
    if (pass.empty()) {
        throw std::invalid_argument("Password cannot be empty");
    }
    
    username.assign(user.begin(), user.end());
    password.assign(pass.begin(), pass.end());
}

// Destructor: securely wipe memory
Credentials::~Credentials() {
    secureClear();
}

// Secure zeroize both buffers
void Credentials::secureClear() {
    if (!username.empty()) {
        CryptoUtils::secureZero(username.data(), username.size());
        username.clear();
    }
    if (!password.empty()) {
        CryptoUtils::secureZero(password.data(), password.size());
        password.clear();
    }
}

// Accessors (converted to string copies)
string Credentials::getUsername() const {
    return string(username.begin(), username.end());
}

string Credentials::getPassword() const {
    return string(password.begin(), password.end());
}

// Get raw bytes (for cryptographic operations)
const std::vector<uint8_t>& Credentials::getUsernameBytes() const {
    return username;
}

const std::vector<uint8_t>& Credentials::getPasswordBytes() const {
    return password;
}

// Manual clear (in case you want to clear before destruction)
void Credentials::clear() {
    secureClear();
}