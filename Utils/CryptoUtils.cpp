#include "CryptoUtils.hpp"
#include <climits>

// Helper: safe check wrapper
static inline void check_alloc(size_t n, const char* ctx) {
    ensure_reasonable_size(n, ctx);
}

// Base64 implementation
namespace Base64 {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    static inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    std::string encode(const std::vector<uint8_t>& data) {
        // small inputs fast path
        if (data.empty()) return std::string();

        std::string ret;
        ret.reserve(((data.size() + 2) / 3) * 4);
        int i = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];
        const unsigned char* bytes_to_encode = data.data();
        size_t in_len = data.size();

        while (in_len--) {
            char_array_3[i++] = *(bytes_to_encode++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                for (i = 0; i < 4; i++) ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for (int j = i; j < 3; j++) char_array_3[j] = '\0';
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (int j = 0; j < i + 1; j++) ret += base64_chars[char_array_4[j]];
            while (i++ < 3) ret += '=';
        }
        return ret;
    }

    std::vector<uint8_t> decode(const std::string& encoded_string) {
        // simple sanity: base64 expands roughly by 3/4; ensure length reasonable
        if (encoded_string.empty()) return {};
        size_t max_decoded = (encoded_string.size() / 4) * 3 + 3;
        check_alloc(max_decoded, "Base64::decode output");

        size_t in_len = encoded_string.size();
        size_t i = 0, j = 0, in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::vector<uint8_t> ret;
        ret.reserve(max_decoded);

        while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++) char_array_4[i] = (unsigned char)base64_chars.find(char_array_4[i]);
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
                for (i = 0; i < 3; i++) ret.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++) char_array_4[j] = 0;
            for (j = 0; j < 4; j++) char_array_4[j] = (unsigned char)base64_chars.find(char_array_4[j]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (j = 0; j < i - 1; j++) ret.push_back(char_array_3[j]);
        }
        return ret;
    }
} // namespace Base64

// JSON ADL macros
#define GET_JSON_FIELD(j, var, type, decoder) \
    if (j.contains(#var)) { p.var = decoder(j.at(#var).get<std::string>()); } \
    else { throw std::runtime_error("JSON missing field: " #var); }

#define GET_JSON_FIELD_RAW(j, var, type) \
    if (j.contains(#var)) { p.var = j.at(#var).get<type>(); } \
    else { throw std::runtime_error("JSON missing field: " #var); }

// Implement ADL conversions
void to_json(json& j, const MetaData& p) {
    j = json{{"timestamp", p.timestamp}, {"description", p.description}};
}
void from_json(const json& j, MetaData& p) {
    GET_JSON_FIELD_RAW(j, timestamp, std::string);
    GET_JSON_FIELD_RAW(j, description, std::string);
}

void to_json(json& j, const PbkdfParams& p) {
    j = json{{"salt", Base64::encode(p.salt)}, {"iterations", p.iterations}, {"keySize", p.keySize}};
}
void from_json(const json& j, PbkdfParams& p) {
    GET_JSON_FIELD(j, salt, std::vector<uint8_t>, Base64::decode);
    GET_JSON_FIELD_RAW(j, iterations, int);
    GET_JSON_FIELD_RAW(j, keySize, int);
}

void to_json(json& j, const AesGcmParams& p) {
    j = json{{"iv", Base64::encode(p.iv)}, {"tag", Base64::encode(p.tag)}, {"aad", Base64::encode(p.aad)}};
}
void from_json(const json& j, AesGcmParams& p) {
    GET_JSON_FIELD(j, iv, std::vector<uint8_t>, Base64::decode);
    GET_JSON_FIELD(j, tag, std::vector<uint8_t>, Base64::decode);
    GET_JSON_FIELD(j, aad, std::vector<uint8_t>, Base64::decode);
}

void to_json(json& j, const EncryptedPacket& p) {
    j = json{{"cipherText", Base64::encode(p.cipherText)}, {"aesParams", p.aesParams}, {"metadata", p.metadata}};
    if (p.pbkdfParams) j["pbkdfParams"] = *p.pbkdfParams;
}
void from_json(const json& j, EncryptedPacket& p) {
    GET_JSON_FIELD(j, cipherText, std::vector<uint8_t>, Base64::decode);
    GET_JSON_FIELD_RAW(j, aesParams, AesGcmParams);
    GET_JSON_FIELD_RAW(j, metadata, MetaData);
    if (j.contains("pbkdfParams")) p.pbkdfParams = std::make_unique<PbkdfParams>(j.at("pbkdfParams").get<PbkdfParams>());
}

// CryptoGlobalInit
CryptoGlobalInit::CryptoGlobalInit() {
    if (wolfSSL_Init() != SSL_SUCCESS) throw std::runtime_error("Failed to initialize wolfSSL library");
}
CryptoGlobalInit::~CryptoGlobalInit() { wolfSSL_Cleanup(); }

// --- CryptoUtils Implementation ---

EncryptedPacket CryptoUtils::encryptData(const std::vector<uint8_t>& plainText,
                                        const std::vector<uint8_t>& key,
                                        const MetaData& meta) {
    if (key.size() != 32) throw std::invalid_argument("Encryption key must be 32 bytes for AES-256");

    // Sanity checks
    check_alloc(plainText.size(), "encryptData plainText");
    check_alloc(key.size(), "encryptData key");
    check_alloc(meta.description.size(), "encryptData meta.description");

    EncryptedPacket packet;
    packet.metadata = meta;

    // IV
    packet.aesParams.iv = genRandom(IV_SIZE);

    // Tag
    packet.aesParams.tag.resize(TAG_SIZE);

    // AAD: metadata JSON bytes
    json metaJson = meta;
    std::string metaDump = metaJson.dump();
    check_alloc(metaDump.size(), "encryptData metaJson dump");
    packet.aesParams.aad.assign(metaDump.begin(), metaDump.end());

    // Ciphertext buffer
    check_alloc(plainText.size(), "encryptData cipherText");
    packet.cipherText.resize(plainText.size());

    // Set key and encrypt
    Aes aes;
    if (wc_AesGcmSetKey(&aes, key.data(), (word32)key.size()) != 0) throw std::runtime_error("wc_AesGcmSetKey failed");

    if (wc_AesGcmEncrypt(&aes,
                         packet.cipherText.data(),
                         plainText.data(),
                         (word32)plainText.size(),
                         packet.aesParams.iv.data(), (word32)packet.aesParams.iv.size(),
                         packet.aesParams.tag.data(), (word32)packet.aesParams.tag.size(),
                         packet.aesParams.aad.data(), (word32)packet.aesParams.aad.size()) != 0) {
        throw std::runtime_error("wc_AesGcmEncrypt failed");
    }

    return packet;
}

std::vector<uint8_t> CryptoUtils::decryptData(const EncryptedPacket& packet,
                                              const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::invalid_argument("Decryption key must be 32 bytes for AES-256");
    check_alloc(key.size(), "decryptData key");
    check_alloc(packet.cipherText.size(), "decryptData cipherText");

    std::vector<uint8_t> plainText;
    plainText.resize(packet.cipherText.size());

    Aes aes;
    if (wc_AesGcmSetKey(&aes, key.data(), (word32)key.size()) != 0) throw std::runtime_error("wc_AesGcmSetKey failed");

    const AesGcmParams& params = packet.aesParams;
    if (wc_AesGcmDecrypt(&aes,
                         plainText.data(),
                         packet.cipherText.data(), (word32)packet.cipherText.size(),
                         params.iv.data(), (word32)params.iv.size(),
                         params.tag.data(), (word32)params.tag.size(),
                         params.aad.data(), (word32)params.aad.size()) != 0) {
        throw std::runtime_error("wc_AesGcmDecrypt failed (authentication failed)");
    }
    return plainText;
}

std::vector<uint8_t> CryptoUtils::deriveKeyFromPassword(const std::string& password,
                                                        const PbkdfParams& params) {
    check_alloc(params.salt.size(), "deriveKeyFromPassword salt");
    if (params.keySize <= 0) throw std::invalid_argument("deriveKeyFromPassword invalid keySize");

    std::vector<uint8_t> key((size_t)params.keySize);
    std::vector<uint8_t> pass(password.begin(), password.end());
    check_alloc(pass.size(), "deriveKeyFromPassword password");

    if (wc_PBKDF2(key.data(), pass.data(), (word32)pass.size(),
                  params.salt.data(), (word32)params.salt.size(),
                  params.iterations, (word32)params.keySize, WC_SHA512) != 0) {
        secureZero(pass);
        throw std::runtime_error("wc_PBKDF2 failed");
    }
    secureZero(pass);
    return key;
}

std::vector<uint8_t> CryptoUtils::subKey(const std::vector<uint8_t>& masterKey,
                                         const std::string& info,
                                         size_t keySize) {
    check_alloc(masterKey.size(), "subKey masterKey");
    check_alloc(info.size(), "subKey info");
    if (keySize == 0) throw std::invalid_argument("subKey keySize=0");

    std::vector<uint8_t> derivedKey(keySize);
    std::vector<uint8_t> infoVec(info.begin(), info.end());

    if (wc_HKDF_Expand(WC_SHA512, masterKey.data(), (word32)masterKey.size(),
                       infoVec.data(), (word32)infoVec.size(),
                       derivedKey.data(), (word32)derivedKey.size()) != 0) {
        throw std::runtime_error("wc_HKDF_Expand failed");
    }
    return derivedKey;
}

std::vector<uint8_t> CryptoUtils::genSalt(size_t size) {
    check_alloc(size, "genSalt");
    return genRandom(size);
}

EcKeyPairPtr CryptoUtils::genSignKeyPair() {
    auto keyPair = std::make_unique<EcKeyPair>();
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) throw std::runtime_error("wc_InitRng failed");
    if (wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &keyPair->key) != 0) {
        wc_FreeRng(&rng);
        throw std::runtime_error("wc_ed25519_make_key failed");
    }
    wc_FreeRng(&rng);
    return keyPair;
}

std::vector<uint8_t> CryptoUtils::exportSignPublicKey(const EcKeyPair& keyPair) {
    std::vector<uint8_t> pubKey(ED25519_KEY_SIZE);
    word32 pubKeySize = (word32)pubKey.size();
    if (wc_ed25519_export_public(const_cast<ed25519_key*>(&keyPair.key), pubKey.data(), &pubKeySize) != 0)
        throw std::runtime_error("wc_ed25519_export_public failed");
    pubKey.resize(pubKeySize);
    return pubKey;
}

DhKeyPairPtr CryptoUtils::genDhKeyPair() {
    auto keyPair = std::make_unique<DhKeyPair>();
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) throw std::runtime_error("wc_InitRng failed");

    if (wc_curve25519_make_key(&rng, (word32)CURVE25519_KEY_SIZE, &keyPair->privateKey) != 0) {
        wc_FreeRng(&rng);
        throw std::runtime_error("wc_curve25519_make_key failed");
    }

    keyPair->publicKey.resize(CURVE25519_KEY_SIZE);
    word32 pubLen = (word32)keyPair->publicKey.size();
    if (wc_curve25519_export_public(&keyPair->privateKey, keyPair->publicKey.data(), &pubLen) != 0) {
        wc_FreeRng(&rng);
        throw std::runtime_error("wc_curve25519_export_public failed");
    }
    keyPair->publicKey.resize(pubLen);
    wc_FreeRng(&rng);
    return keyPair;
}

std::vector<uint8_t> CryptoUtils::genSharedSecret(const DhKeyPair& myKey,
                                                  const std::vector<uint8_t>& theirPublicKey) {
    if (theirPublicKey.size() != CURVE25519_KEY_SIZE) throw std::invalid_argument("Invalid Curve25519 public key size");
    check_alloc(theirPublicKey.size(), "genSharedSecret theirPublicKey");

    std::vector<uint8_t> sharedSecret(CURVE25519_KEY_SIZE);
    curve25519_key theirKey;
    wc_curve25519_init(&theirKey);
    if (wc_curve25519_import_public(theirPublicKey.data(), (word32)theirPublicKey.size(), &theirKey) != 0) {
        wc_curve25519_free(&theirKey);
        throw std::runtime_error("wc_curve25519_import_public failed");
    }

    word32 outLen = (word32)sharedSecret.size();
    if (wc_curve25519_shared_secret(const_cast<curve25519_key*>(&myKey.privateKey),
                                    &theirKey, sharedSecret.data(), &outLen) != 0) {
        wc_curve25519_free(&theirKey);
        throw std::runtime_error("wc_curve25519_shared_secret failed");
    }

    sharedSecret.resize(outLen);
    wc_curve25519_free(&theirKey);
    return sharedSecret;
}

std::vector<uint8_t> CryptoUtils::genSignature(const std::vector<uint8_t>& hash,
                                               const EcKeyPair& keyPair) {
    if (hash.size() != HASH_SIZE) throw std::invalid_argument("Hash for signing must be SHA-512 (64 bytes)");
    std::vector<uint8_t> signature(ED25519_SIG_SIZE);
    word32 sigLen = (word32)signature.size();
    if (wc_ed25519_sign_msg(hash.data(), (word32)hash.size(), signature.data(), &sigLen,
                             const_cast<ed25519_key*>(&keyPair.key)) != 0) throw std::runtime_error("wc_ed25519_sign_msg failed");
    signature.resize(sigLen);
    return signature;
}

bool CryptoUtils::verifySignature(const std::vector<uint8_t>& hash,
                                  const std::vector<uint8_t>& signature,
                                  const std::vector<uint8_t>& publicKey) {
    if (hash.size() != HASH_SIZE || signature.size() != ED25519_SIG_SIZE || publicKey.size() != ED25519_KEY_SIZE) return false;
    ed25519_key pubKey;
    if (wc_ed25519_init(&pubKey) != 0) return false;
    if (wc_ed25519_import_public(publicKey.data(), (word32)publicKey.size(), &pubKey) != 0) {
        wc_ed25519_free(&pubKey);
        return false;
    }
    int verified = 0;
    int ret = wc_ed25519_verify_msg(signature.data(), (word32)signature.size(), hash.data(), (word32)hash.size(), &verified, &pubKey);
    wc_ed25519_free(&pubKey);
    return (ret == 0 && verified == 1);
}

std::vector<uint8_t> CryptoUtils::calculateHash(const std::vector<uint8_t>& data) {
    check_alloc(data.size(), "calculateHash data");
    std::vector<uint8_t> hash(HASH_SIZE);
    if (wc_Sha512Hash(data.data(), (word32)data.size(), hash.data()) != 0) throw std::runtime_error("wc_Sha512Hash failed");
    return hash;
}

bool CryptoUtils::verifyHash(const std::vector<uint8_t>& hash1,
                             const std::vector<uint8_t>& hash2) {
    if (hash1.size() != hash2.size()) return false;
    return portable_const_time_eq(hash1.data(), hash2.data(), hash1.size());
}

std::vector<uint8_t> CryptoUtils::genRandom(size_t size) {
    check_alloc(size, "genRandom");
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) throw std::runtime_error("wc_InitRng failed");
    std::vector<uint8_t> buffer(size);
    if (wc_RNG_GenerateBlock(&rng, buffer.data(), (word32)buffer.size()) != 0) {
        wc_FreeRng(&rng);
        throw std::runtime_error("wc_RNG_GenerateBlock failed");
    }
    wc_FreeRng(&rng);
    return buffer;
}

void CryptoUtils::secureZero(std::vector<uint8_t>& vec) {
    if (!vec.empty()) portable_secure_zero(vec.data(), vec.size());
}

void CryptoUtils::print_hex(const std::string& title, const std::vector<uint8_t>& data) {
    std::cout << title << " (" << data.size() << " bytes):" << std::endl;
    std::cout << "    ";
    std::ios_base::fmtflags f(std::cout.flags());
    for (const auto& byte : data) {
        std::cout << "0x" << std::hex << std::uppercase << std::setw(2)
                  << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    std::cout.flags(f);
}
