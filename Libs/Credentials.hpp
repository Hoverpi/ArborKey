#pragma once
#ifndef CREDENTIALS_HPP
#define CREDENTIALS_HPP

#include "thirdparty.hpp"
#include "CryptoUtils.hpp"

class Credentials {
private:
    std::vector<uint8_t> username;
    std::vector<uint8_t> password;
    
    void secureClear();

public:
    // Constructor: interactive prompt
    Credentials();
    
    // Constructor: with provided values
    Credentials(const string& user, const string& pass);
    
    // Destructor: secure cleanup
    ~Credentials();
    
    // Accessors (returns copies)
    string getUsername() const;
    string getPassword() const;
    
    // Get raw bytes (for cryptographic operations)
    const std::vector<uint8_t>& getUsernameBytes() const;
    const std::vector<uint8_t>& getPasswordBytes() const;
    
    // Manual clear (in case you want to clear before destruction)
    void clear();
    
    // Disable copy/move to prevent accidental duplication of sensitive data
    Credentials(const Credentials&) = delete;
    Credentials& operator=(const Credentials&) = delete;
    Credentials(Credentials&&) = delete;
    Credentials& operator=(Credentials&&) = delete;
};

#endif