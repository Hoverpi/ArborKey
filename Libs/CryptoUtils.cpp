#include "CryptoUtils.hpp"

// EcKeyPair implementation
EcKeyPair::EcKeyPair() {
    if (wc_ed25519_init(&key) != 0) 
        throw std::runtime_error("Failed to init ed25519_key");
}

EcKeyPair::~EcKeyPair() { 
    wc_ed25519_free(&key); 
}

// DhKeyPair implementation
DhKeyPair::DhKeyPair() { 
    wc_curve25519_init(&privateKey); 
}

DhKeyPair::~DhKeyPair() {
    wc_curve25519_free(&privateKey);
    if (!publicKey.empty()) 
        CryptoUtils::secureZero(publicKey.data(), publicKey.size());
}

// Helper: safe check wrapper
static inline void check_alloc(size_t n, const char* ctx) {
    ensure_reasonable_size(n, ctx);
}

// Base64 implementation
namespace Base64 {
    static const string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    static inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    string encode(const std::vector<uint8_t>& data) {
        // small inputs fast path
        if (data.empty()) return string();

        string ret;
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

    std::vector<uint8_t> decode(const string& encoded_string) {
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

// CryptoGlobalInit
CryptoGlobalInit::CryptoGlobalInit() {
    if (wolfSSL_Init() != SSL_SUCCESS) throw std::runtime_error("Failed to initialize wolfSSL library");
}
CryptoGlobalInit::~CryptoGlobalInit() { wolfSSL_Cleanup(); }

// process username
string CryptoUtils::genVaultId() {
    std::vector<uint8_t> vaultId = CryptoUtils::genRandom(32);
    return Base64::encode(vaultId);
}

Entry CryptoUtils::createEntry(const string& id_user, const string& title, const string& url, const EncryptedPacket& ep) {
    Entry entry;
    entry.id = id_user;
    entry.title = title;
    entry.md.url = url;
    entry.ep = ep;
    return entry;
}

// ---------- vault -> json ----------
json CryptoUtils::vaultToJson(const Vault& v) {
    json j;
    j["id"] = v.id;
    j["user"] = v.username;

    // master-key
    j["master-key"]["dmk_alg"] = v.mk.alg;
    j["master-key"]["params"]["salt"] = v.mk.masterParams.salt;
    j["master-key"]["params"]["iterations"] = v.mk.masterParams.iterations;
    j["master-key"]["params"]["keySize"] = v.mk.masterParams.keySize;

    // sub-key
    j["sub-key"]["params"]["hashType"] = v.sk.subParams.hashType;
    j["sub-key"]["params"]["salt"] = v.sk.subParams.salt;
    j["sub-key"]["params"]["keySize"] = v.sk.subParams.keySize;

    // enc-packet for sub-key (map field names to your expected JSON)
    j["sub-key"]["enc-packet"]["alg"] = v.sk.ep.alg;
    j["sub-key"]["enc-packet"]["iv"] = v.sk.ep.iv;
    j["sub-key"]["enc-packet"]["cipher"] = v.sk.ep.cipherData;
    j["sub-key"]["enc-packet"]["tag"] = v.sk.ep.tag;
    j["sub-key"]["enc-packet"]["aad"] = v.sk.ep.aad;

    // entries array
    j["entries"] = json::array();
    for (const auto& e : v.entries) {
        json ej;
        ej["id"] = e.id;
        ej["title"] = e.title;
        ej["meta-data"]["url"] = e.md.url;
        ej["meta-data"]["created"] = e.md.timestamp;
        ej["enc-packet"]["alg"] = e.ep.alg;
        ej["enc-packet"]["iv"] = e.ep.iv;
        ej["enc-packet"]["cipher"] = e.ep.cipherData;
        ej["enc-packet"]["tag"] = e.ep.tag;
        ej["enc-packet"]["aad"] = e.ep.aad;
        j["entries"].push_back(ej);
    }

    return j;
}

// ---------- json -> vault ----------
Vault CryptoUtils::vaultFromJson(const json& j) {
    // Basic validation
    if (!j.is_object()) throw std::runtime_error("vaultFromJson: json is not an object");

    Vault v;
    // top-level id & user
    if (j.contains("id") && j["id"].is_string()) v.id = j["id"].get<string>();
    else throw std::runtime_error("vaultFromJson: missing 'id'");

    if (j.contains("user") && j["user"].is_string()) v.username = j["user"].get<string>();
    else throw std::runtime_error("vaultFromJson: missing 'user'");

    // master-key
    if (j.contains("master-key")) {
        const auto& mk = j["master-key"];
        if (mk.contains("dmk_alg") && mk["dmk_alg"].is_string()) v.mk.alg = mk["dmk_alg"].get<string>();
        if (mk.contains("params")) {
            const auto& p = mk["params"];
            if (p.contains("salt") && p["salt"].is_string()) v.mk.masterParams.salt = p["salt"].get<string>();
            if (p.contains("iterations") && p["iterations"].is_number_unsigned()) v.mk.masterParams.iterations = p["iterations"].get<uint32_t>();
            if (p.contains("keySize") && p["keySize"].is_number_unsigned()) v.mk.masterParams.keySize = p["keySize"].get<uint32_t>();
        }
    }

    // sub-key
    if (j.contains("sub-key")) {
        const auto& sk = j["sub-key"];
        if (sk.contains("params")) {
            const auto& p = sk["params"];
            if (p.contains("hashType") && p["hashType"].is_string()) v.sk.subParams.hashType = p["hashType"].get<string>();
            if (p.contains("salt") && p["salt"].is_string()) v.sk.subParams.salt = p["salt"].get<string>();
            if (p.contains("keySize") && p["keySize"].is_number_unsigned()) v.sk.subParams.keySize = p["keySize"].get<uint32_t>();
        }
        if (sk.contains("enc-packet")) {
            const auto& epj = sk["enc-packet"];
            if (epj.contains("alg") && epj["alg"].is_string()) v.sk.ep.alg = epj["alg"].get<string>();
            if (epj.contains("iv") && epj["iv"].is_string()) v.sk.ep.iv = epj["iv"].get<string>();
            if (epj.contains("cipher") && epj["cipher"].is_string()) v.sk.ep.cipherData = epj["cipher"].get<string>();
            if (epj.contains("tag") && epj["tag"].is_string()) v.sk.ep.tag = epj["tag"].get<string>();
            if (epj.contains("aad") && epj["aad"].is_string()) v.sk.ep.aad = epj["aad"].get<string>();
        }
    }

    // entries
    v.entries.clear();
    if (j.contains("entries") && j["entries"].is_array()) {
        for (const auto& ej : j["entries"]) {
            Entry e;
            if (ej.contains("id") && ej["id"].is_string()) e.id = ej["id"].get<string>();
            else throw std::runtime_error("vaultFromJson: entry missing id");
            if (ej.contains("title") && ej["title"].is_string()) e.title = ej["title"].get<string>();
            if (ej.contains("meta-data")) {
                const auto& mdj = ej["meta-data"];
                if (mdj.contains("url") && mdj["url"].is_string()) e.md.url = mdj["url"].get<string>();
                if (mdj.contains("created") && mdj["created"].is_string()) e.md.timestamp = mdj["created"].get<string>();
            }
            if (ej.contains("enc-packet")) {
                const auto& epj = ej["enc-packet"];
                if (epj.contains("alg") && epj["alg"].is_string()) e.ep.alg = epj["alg"].get<string>();
                if (epj.contains("iv") && epj["iv"].is_string()) e.ep.iv = epj["iv"].get<string>();
                if (epj.contains("cipher") && epj["cipher"].is_string()) e.ep.cipherData = epj["cipher"].get<string>();
                if (epj.contains("tag") && epj["tag"].is_string()) e.ep.tag = epj["tag"].get<string>();
                if (epj.contains("aad") && epj["aad"].is_string()) e.ep.aad = epj["aad"].get<string>();
            }
            v.entries.push_back(std::move(e));
        }
    }

    return v;
}

// --- toFile: serialize and write a vault to disk atomically ---
void CryptoUtils::toFile(const Vault& v, const string& filepath) {
    json j = vaultToJson(v);

    // Write to a temporary file first
    string tmpPath = filepath + ".tmp";
    std::ofstream ofs(tmpPath, std::ios::out | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error("toFile: cannot open temporary file for writing: " + tmpPath);
    }

    // Write pretty-printed JSON and flush
    ofs << j.dump(2);
    ofs.flush();
    if (!ofs) {
        // Attempt to remove temporary file on write failure, then throw
        std::error_code rem_ec;
        std::filesystem::remove(tmpPath, rem_ec);
        throw std::runtime_error("toFile: write failed to temporary file: " + tmpPath);
    }
    ofs.close();

    // Rename temporary -> final (rename is atomic on most OSes)
    std::error_code ec;
    std::filesystem::rename(tmpPath, filepath, ec);
    if (ec) {
        // Remove temp if rename failed, then throw
        std::filesystem::remove(tmpPath);
        throw std::runtime_error(string("toFile: rename failed: ") + ec.message());
    }

#ifndef _WIN32
    // 4) Try to set POSIX permissions to owner read/write only (best-effort)
    std::error_code perm_ec;
    std::filesystem::permissions(filepath,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace,
                                 perm_ec);
    // Do not fail if setting permissions is unsupported; ignore perm_ec
    (void)perm_ec;
#endif
}

// --- fromFile: read, parse and reconstruct a Vault from disk ---
Vault CryptoUtils::fromFile(const string& filepath) {
    // Open file for reading (binary mode)
    std::ifstream ifs(filepath, std::ios::in | std::ios::binary);
    if (!ifs) throw std::runtime_error("fromFile: cannot open file: " + filepath);

    // Read entire file content into a string
    string content;
    ifs.seekg(0, std::ios::end);
    std::streampos size = ifs.tellg();
    if (size > 0) {
        content.reserve(static_cast<size_t>(size));
        ifs.seekg(0, std::ios::beg);
        content.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    } else {
        // Empty file is treated as an error
        throw std::runtime_error("fromFile: file is empty: " + filepath);
    }
    ifs.close();

    // Parse JSON from the string (may throw nlohmann::ordered_json::parse_error)
    json j;
    try {
        j = nlohmann::ordered_json::parse(content);
    } catch (const nlohmann::ordered_json::parse_error& e) {
        // Wipe content buffer before rethrowing to reduce plaintext lifetime
        std::fill(content.begin(), content.end(), '\0');
        throw std::runtime_error(string("fromFile: JSON parse error: ") + e.what());
    }

    // 4) Overwrite the content buffer to reduce lifetime of sensitive data in memory
    std::fill(content.begin(), content.end(), '\0');

    // 5) Convert parsed JSON into a Vault object (vaultFromJson may throw)
    Vault v = vaultFromJson(j);

    return v;
}


// --- CryptoUtils Implementation ---

EncryptedPacket CryptoUtils::encryptData(const std::vector<uint8_t>& plainText, const std::vector<uint8_t>& key, const string aadStr) {
    if (key.size() != 32) throw std::invalid_argument("Encryption key must be 32 bytes for AES-256");

    // Sanity checks
    check_alloc(plainText.size(), "encryptData plainText");
    check_alloc(key.size(), "encryptData key");

    EncryptedPacket ep;
    ep.alg = "aes-256-gcm";
    std::vector<uint8_t> iv(CryptoUtils::IV_SIZE);
    iv = CryptoUtils::genRandom(CryptoUtils::IV_SIZE);
    std::vector<uint8_t> tag(CryptoUtils::TAG_SIZE);
    std::vector<uint8_t> aad(aadStr.begin(), aadStr.end());
    check_alloc(aad.size(), "convert aad to vector");

    std::vector<uint8_t> cipherData(plainText.size());

    // Set key and encrypt
    Aes aes;
    if (wc_AesGcmSetKey(&aes, key.data(), (word32)key.size()) != 0) throw std::runtime_error("wc_AesGcmSetKey failed");

    if (wc_AesGcmEncrypt(&aes,
                        cipherData.data(),
                        plainText.data(),
                        (word32)plainText.size(),
                        iv.data(), (word32)iv.size(),
                        tag.data(), (word32)tag.size(),
                        aad.data(), (word32)aad.size()) != 0) {
        throw std::runtime_error("wc_AesGcmEncrypt failed");
    }

    // encode
    ep.iv = Base64::encode(iv);
    ep.cipherData = Base64::encode(cipherData);
    ep.tag = Base64::encode(tag);
    ep.aad = Base64::encode(aad);

    return ep;
}

std::vector<uint8_t> CryptoUtils::decryptData(const EncryptedPacket& ep, const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::invalid_argument("Decryption key must be 32 bytes for AES-256");
    check_alloc(key.size(), "decryptData key");

    // First decode the base64 fields (so we know the real ciphertext length)
    std::vector<uint8_t> iv = Base64::decode(ep.iv);
    std::vector<uint8_t> cipherData = Base64::decode(ep.cipherData);
    std::vector<uint8_t> tag = Base64::decode(ep.tag);
    std::vector<uint8_t> aad = Base64::decode(ep.aad);

    // Basic sanity checks after decode
    check_alloc(iv.size(), "decryptData iv");
    check_alloc(cipherData.size(), "decryptData cipherData");
    check_alloc(tag.size(), "decryptData tag");

    Aes aes;
    if (wc_AesGcmSetKey(&aes, key.data(), (word32)key.size()) != 0) throw std::runtime_error("wc_AesGcmSetKey failed");

    // Resize plaintext to exact cipher size (AES-GCM plaintext == ciphertext length)
    std::vector<uint8_t> plainText;
    plainText.resize(cipherData.size());

    if (wc_AesGcmDecrypt(&aes,
                        plainText.data(),
                        cipherData.data(), (word32)cipherData.size(),
                        iv.data(), (word32)iv.size(),
                        tag.data(), (word32)tag.size(),
                        aad.data(), (word32)aad.size()) != 0) {
        throw std::runtime_error("wc_AesGcmDecrypt failed (authentication failed)");
    }
    return plainText;
}

std::vector<uint8_t> CryptoUtils::calculateDerivedKey(const string& password, MasterKey& mk, std::vector<uint8_t>& outSalt) {
    check_alloc(outSalt.size(), "calculateDerivedKey outSalt");
    if (mk.masterParams.keySize <= 0) throw std::invalid_argument("calculateDerivedKey invalid keySize");

    std::vector<uint8_t> key((size_t)mk.masterParams.keySize);
    std::vector<uint8_t> pass(password.begin(), password.end());
    check_alloc(pass.size(), "calculateDerivedKey password");

    if (wc_PBKDF2(key.data(), pass.data(), (word32)pass.size(), outSalt.data(), (word32)outSalt.size(),
                mk.masterParams.iterations, (word32)mk.masterParams.keySize, WC_SHA512) != 0) {
        CryptoUtils::secureZero(pass.data(), pass.size());
        CryptoUtils::secureZero(key.data(), key.size());

        throw std::runtime_error("wc_PBKDF2 failed");
    }
    CryptoUtils::secureZero(pass.data(), pass.size());

    // persist salt as Base64 in mk
    mk.masterParams.salt = Base64::encode(outSalt);
    mk.alg = "PBKDF2-HMAC-SHA512";

    return key;
}

bool CryptoUtils::verifyDerivedKey(const string& password, const MasterKey& mk, const std::vector<uint8_t>& expectedDerived) {
    if (expectedDerived.empty()) return false;
    if (mk.masterParams.salt.empty()) return false;

    // decode salt from mk
    std::vector<uint8_t> salt = Base64::decode(mk.masterParams.salt);
    if (salt.empty()) return false;

    std::vector<uint8_t> recomputed((size_t)mk.masterParams.keySize);
    std::vector<uint8_t> pass(password.begin(), password.end());

    if (wc_PBKDF2(recomputed.data(),
                pass.data(), (word32)pass.size(),
                salt.data(), (word32)salt.size(),
                mk.masterParams.iterations,
                (word32)mk.masterParams.keySize,
                WC_SHA512) != 0) {
        CryptoUtils::secureZero(pass.data(), pass.size());
        return false;
    }
    CryptoUtils::secureZero(pass.data(), pass.size());

    // compare BEFORE zeroing recomputed
    bool ok = false;
    if (recomputed.size() == expectedDerived.size()) {
        ok = CryptoUtils::verifyHash(recomputed, expectedDerived);
    } else {
        ok = false;
    }

    // wipe recomputed
    CryptoUtils::secureZero(recomputed.data(), recomputed.size());

    return ok;
}

void CryptoUtils::calculateSubKey(const std::vector<uint8_t>& masterKey, const string& info, SubKey& sk) {
    check_alloc(masterKey.size(), "subKey masterKey");
    check_alloc(info.size(), "subKey info");
    if (sk.subParams.keySize == 0) throw std::invalid_argument("subKey keySize=0");

    // 1) Prepare salt: generate if not present
    std::vector<uint8_t> salt;
    if (!sk.subParams.salt.empty()) {
        salt = Base64::decode(sk.subParams.salt);
        if (salt.empty()) throw std::runtime_error("Invalid base64 salt in sk.subParams.salt");
    } else {
        salt = CryptoUtils::genSalt(CryptoUtils::SALT_SIZE);
        sk.subParams.salt = Base64::encode(salt); // persist salt base64
    }
    check_alloc(salt.size(), "subKey salt");

    // HKDF derive using wolfSSL wc_HKDF (HMAC-SHA512)
    std::vector<uint8_t> derived((size_t)sk.subParams.keySize);
    if (wc_HKDF(WC_SHA512, reinterpret_cast<const byte*>(masterKey.data()), (word32)masterKey.size(), salt.data(), (word32)salt.size(),
                    reinterpret_cast<const byte*>(info.data()), (word32)info.size(), derived.data(), (word32)derived.size()) != 0) {
        CryptoUtils::secureZero(derived.data(), derived.size());
        throw std::runtime_error("wc_HKDF failed in calculateSubKey");
    }

    // Hash the derived subkey
    std::vector<uint8_t> hashDerived = CryptoUtils::calculateHash(derived);

    // Build deterministic AAD and encrypt the hash with the masterKey
    string aadSubKey = info + ":subkey";
    sk.ep = CryptoUtils::encryptData(hashDerived, masterKey, aadSubKey);

    CryptoUtils::secureZero(derived.data(), derived.size());
    CryptoUtils::secureZero(hashDerived.data(), hashDerived.size());
    CryptoUtils::secureZero(salt.data(), salt.size());
}

bool CryptoUtils::verifySubKey(const std::vector<uint8_t>& sessionMasterKey, const SubKey& sk, const string& info) {
    if (sessionMasterKey.empty()) return false;
    if (sk.subParams.keySize == 0) return false;
    if (sk.subParams.salt.empty()) return false;

    // Decode salt
    std::vector<uint8_t> salt = Base64::decode(sk.subParams.salt);
    if (salt.empty()) return false;

    // Recompute deterministic AAD string from stored info and decode AAD bytes that were stored in ep
    std::vector<uint8_t> aad_bytes;
    if (!sk.ep.aad.empty()) {
        aad_bytes = Base64::decode(sk.ep.aad);
    }
    string aad_str(aad_bytes.begin(), aad_bytes.end());

    // Decrypt stored hashed subkey (AAD must match)
    std::vector<uint8_t> storedHash;
    
    storedHash = CryptoUtils::decryptData(sk.ep, sessionMasterKey);

    if (storedHash.size() != CryptoUtils::HASH_SIZE) return false;

    // Re-derive the subkey with the same salt and info
    std::vector<uint8_t> recomputed((size_t)sk.subParams.keySize);
    if (wc_HKDF(WC_SHA512, reinterpret_cast<const byte*>(sessionMasterKey.data()), (word32)sessionMasterKey.size(), salt.data(), (word32)salt.size(),
                    reinterpret_cast<const byte*>(info.data()), (word32)info.size(), recomputed.data(), (word32)recomputed.size()) != 0) {
        CryptoUtils::secureZero(recomputed.data(), recomputed.size());
        CryptoUtils::secureZero(storedHash.data(), storedHash.size());
        return false;
    }

    // Hash recomputed subkey and compare with stored hash (constant-time)
    std::vector<uint8_t> recomputedHash = CryptoUtils::calculateHash(recomputed);
    // compare BEFORE zeroing recomputed
    bool ok = false;
    if (recomputedHash.size() == storedHash.size()) {
        ok = CryptoUtils::verifyHash(recomputedHash, storedHash);
    } else {
        ok = false;
    }

    // wipe recomputed
    CryptoUtils::secureZero(recomputed.data(), recomputed.size());

    return ok;

    // Wipe sensitive data
    CryptoUtils::secureZero(recomputed.data(), recomputed.size());
    CryptoUtils::secureZero(recomputedHash.data(), recomputedHash.size());
    CryptoUtils::secureZero(storedHash.data(), storedHash.size());
    CryptoUtils::secureZero(salt.data(), salt.size());

    return ok;
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

bool CryptoUtils::verifyHash(const std::vector<uint8_t>& hash1, const std::vector<uint8_t>& hash2) {
    if (hash1.size() != hash2.size()) return false;
    return constEq(hash1.data(), hash2.data(), hash1.size());
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

void CryptoUtils::secureZero(void* p, size_t n) {
    if (p == nullptr || n == 0) return;
    volatile unsigned char *vp = reinterpret_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
}

bool CryptoUtils::constEq(const void* a_, const void* b_, size_t n) {
    if (a_ == nullptr || b_ == nullptr) return false;
    const unsigned char* a = reinterpret_cast<const unsigned char*>(a_);
    const unsigned char* b = reinterpret_cast<const unsigned char*>(b_);
    unsigned char diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

void CryptoUtils::print_hex(const string& title, const std::vector<uint8_t>& data) {
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
