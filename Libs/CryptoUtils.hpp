#pragma once
#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include "thirdparty.hpp"

// Small helper to validate sizes before creating vectors
static inline void ensure_reasonable_size(size_t n, const char* context) {
    size_t max_ok = std::vector<uint8_t>().max_size() / 8;
    if (n == 0) return;
    if (n > max_ok) {
        std::ostringstream ss;
        ss << "Refusing to allocate vector for '" << context << "' of size " << n
           << " (max allowed " << max_ok << ")";
        throw std::runtime_error(ss.str());
    }
}

// --- Key Pair Structs ---
struct EcKeyPair {
    ed25519_key key;
    EcKeyPair();
    ~EcKeyPair();
};

struct DhKeyPair {
    curve25519_key privateKey;
    std::vector<uint8_t> publicKey;
    DhKeyPair();
    ~DhKeyPair();
};

using EcKeyPairPtr = std::unique_ptr<EcKeyPair>;
using DhKeyPairPtr = std::unique_ptr<DhKeyPair>;

// Forward declarations
struct EncryptedPacket;
struct MasterKey;
struct SubKey;
struct Entry;

// EncryptedPacket definition
struct EncryptedPacket {
    string alg;
    string iv;
    string cipherData;
    string tag;
    string aad;
};

// Metadata for an entry
struct MetaData {
    string timestamp;
    string url;
    MetaData(string desc = "") : url(std::move(desc)) {
        char buf[sizeof("YYYY-MM-DDTHH:MM:SSZ")];
        std::time_t now = std::time(nullptr);
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
        timestamp = buf;
    }
};

struct ParamsPBKDF {
    string salt;
    uint32_t iterations = 100000;
    uint32_t keySize = 32;
};

struct MasterKey {
    string alg;
    ParamsPBKDF masterParams;
};

struct ParamsHKDF {
    string hashType;
    string salt;
    uint32_t keySize = 32;
};

struct SubKey {
    ParamsHKDF subParams;
    EncryptedPacket ep;
};

struct Entry {
    string id;  
    string title;
    MetaData md;
    EncryptedPacket ep;
};

struct Vault {
    string id;  
    string username;
    MasterKey mk;
    SubKey sk;
    std::vector<Entry> entries;
};

// Base64 forward declarations
namespace Base64 {
    string encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode(const string& input);
}

// RAII for wolfSSL
class CryptoGlobalInit {
public:
    CryptoGlobalInit();
    ~CryptoGlobalInit();
};

// Crypto utilities interface
class CryptoUtils {
public:
    static constexpr size_t ID_SIZE = 32;
    static constexpr size_t IV_SIZE = 16;
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t SALT_SIZE = 32;
    static constexpr size_t HASH_SIZE = 64;
    static constexpr size_t CURVE25519_KEY_SIZE = 32;

    // process username
    static string genVaultId();

    // Encrypt/Decrypt
    static EncryptedPacket encryptData(const std::vector<uint8_t>& plainText, const std::vector<uint8_t>& key, const string aadStr);

    static std::vector<uint8_t> decryptData(const EncryptedPacket& packet, const std::vector<uint8_t>& key);

    // Master key helpers (single flexible function for both signup and login)
    static std::vector<uint8_t> calculateMasterKey(const std::string &password, MasterKey &mk);

    // Optional helper to verify derived master key against an expected derived value
    static bool verifyMasterKey(const std::string &password, const MasterKey &mk, const std::vector<uint8_t> &expectedDerived);

    // Sub-key helpers (signup: calculateSubKey; login: verifySubKey)
    static void calculateSubKey(const std::vector<uint8_t> &masterKey, const std::string &info, SubKey &sk);
    static bool verifySubKey(const std::vector<uint8_t> &masterKey, const SubKey &sk, const std::string &info);


    // Convenience
    static void genSalt(std::vector<uint8_t>& out, size_t size);

    // Entry creation helper
    static Entry createEntry(const string& id_user, const string& title, const string& url, const EncryptedPacket& ep);

    // Asymmetric
    static EcKeyPairPtr genSignKeyPair();
    static std::vector<uint8_t> exportSignPublicKey(const EcKeyPair& keyPair);
    static DhKeyPairPtr genDhKeyPair();
    static std::vector<uint8_t> genSharedSecret(const DhKeyPair& myKey, const std::vector<uint8_t>& theirPublicKey);

    // Signature
    static std::vector<uint8_t> genSignature(const std::vector<uint8_t>& hash, const EcKeyPair& keyPair);
    static bool verifySignature(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& publicKey);

    // Hash/Utils
    static std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data);
    static bool verifyHash(const std::vector<uint8_t>& hash1, const std::vector<uint8_t>& hash2);

    // Vault <-> JSON helpers
    static json vaultToJson(const Vault& v);
    static Vault vaultFromJson(const json& j);
    static void toFile(const Vault& v, const std::string& filepath);
    static Vault fromFile(const std::string& filepath);

    static void genRandom(std::vector<uint8_t>& out, size_t size);
    static void secureZero(void* p, size_t n);
    static bool constEq(const void* a_, const void* b_, size_t n);
    static void print_hex(const string& title, const std::vector<uint8_t>& data);
};

#endif