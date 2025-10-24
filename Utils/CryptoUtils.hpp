#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <algorithm>

// Include the robust JSON library you requested
#include "json.hpp" // https://github.com/nlohmann/json

// WolfSSL Headers
#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/ssl.h"

// Use nlohmann::json for JSON operations
using json = nlohmann::json;

// ----------------------------
// Portable helpers (header)
// ----------------------------

// Portable secure-zero helper
static inline void portable_secure_zero(void* p, size_t n) {
    if (p == nullptr || n == 0) return;
    volatile unsigned char *vp = reinterpret_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
}

// Portable constant-time compare
static inline bool portable_const_time_eq(const void* a_, const void* b_, size_t n) {
    if (a_ == nullptr || b_ == nullptr) return false;
    const unsigned char* a = reinterpret_cast<const unsigned char*>(a_);
    const unsigned char* b = reinterpret_cast<const unsigned char*>(b_);
    unsigned char diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

// Small helper to validate sizes before creating vectors
static inline void ensure_reasonable_size(size_t n, const char* context) {
    size_t max_ok = std::vector<uint8_t>().max_size() / 8; // be conservative
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
    EcKeyPair() {
        if (wc_ed25519_init(&key) != 0) throw std::runtime_error("Failed to init ed25519_key");
    }
    ~EcKeyPair() { wc_ed25519_free(&key); }
};

struct DhKeyPair {
    curve25519_key privateKey;
    std::vector<uint8_t> publicKey;
    DhKeyPair() { wc_curve25519_init(&privateKey); }
    ~DhKeyPair() {
        portable_secure_zero(&privateKey, sizeof(privateKey));
        wc_curve25519_free(&privateKey);
        if (!publicKey.empty()) portable_secure_zero(publicKey.data(), publicKey.size());
    }
};

using EcKeyPairPtr = std::unique_ptr<EcKeyPair>;
using DhKeyPairPtr = std::unique_ptr<DhKeyPair>;

// --- JSON Data Structures ---
struct MetaData {
    std::string timestamp;
    std::string description;
    MetaData(std::string desc = "") : description(std::move(desc)) {
        char buf[sizeof("YYYY-MM-DDTHH:MM:SSZ")];
        std::time_t now = std::time(nullptr);
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
        timestamp = buf;
    }
};

struct PbkdfParams {
    std::vector<uint8_t> salt;
    int iterations = 4096;
    int keySize = 32;
};

struct AesGcmParams {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> aad;
};

struct EncryptedPacket {
    std::vector<uint8_t> cipherText;
    AesGcmParams aesParams;
    std::unique_ptr<PbkdfParams> pbkdfParams;
    MetaData metadata;
};

// Base64 forward declarations
namespace Base64 {
    std::string encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode(const std::string& input);
}

// JSON ADL forward declarations
void to_json(json& j, const MetaData& p);
void from_json(const json& j, MetaData& p);
void to_json(json& j, const PbkdfParams& p);
void from_json(const json& j, PbkdfParams& p);
void to_json(json& j, const AesGcmParams& p);
void from_json(const json& j, AesGcmParams& p);
void to_json(json& j, const EncryptedPacket& p);
void from_json(const json& j, EncryptedPacket& p);

// RAII for wolfSSL
class CryptoGlobalInit {
public:
    CryptoGlobalInit();
    ~CryptoGlobalInit();
};

// Crypto utilities interface
class CryptoUtils {
public:
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t HASH_SIZE = 64;
    static constexpr size_t CURVE25519_KEY_SIZE = 32;

    // Core
    static EncryptedPacket encryptData(const std::vector<uint8_t>& plainText,
                                       const std::vector<uint8_t>& key,
                                       const MetaData& meta);

    static std::vector<uint8_t> decryptData(const EncryptedPacket& packet,
                                            const std::vector<uint8_t>& key);

    // KDFs
    static std::vector<uint8_t> deriveKeyFromPassword(const std::string& password,
                                                      const PbkdfParams& params);

    static std::vector<uint8_t> subKey(const std::vector<uint8_t>& masterKey,
                                       const std::string& info,
                                       size_t keySize = 32);

    static std::vector<uint8_t> genSalt(size_t size = SALT_SIZE);

    // Asymmetric
    static EcKeyPairPtr genSignKeyPair();
    static std::vector<uint8_t> exportSignPublicKey(const EcKeyPair& keyPair);
    static DhKeyPairPtr genDhKeyPair();
    static std::vector<uint8_t> genSharedSecret(const DhKeyPair& myKey,
                                                const std::vector<uint8_t>& theirPublicKey);

    // Signature
    static std::vector<uint8_t> genSignature(const std::vector<uint8_t>& hash,
                                             const EcKeyPair& keyPair);
    static bool verifySignature(const std::vector<uint8_t>& hash,
                                const std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& publicKey);

    // Hash/Utils
    static std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data);
    static bool verifyHash(const std::vector<uint8_t>& hash1,
                           const std::vector<uint8_t>& hash2);

    static std::vector<uint8_t> genRandom(size_t size);
    static void secureZero(std::vector<uint8_t>& vec);
    static void print_hex(const std::string& title, const std::vector<uint8_t>& data);
};

#endif // CRYPTO_UTILS_HPP
