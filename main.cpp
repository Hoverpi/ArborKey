// main.cpp
#include "CryptoUtils.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>

static void save_json_to_file(const std::string& path, const std::string& jsonStr) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open file for writing: " + path);
    out << jsonStr;
    out.close();
}

static std::string load_json_from_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open file for reading: " + path);
    std::ostringstream ss; ss << in.rdbuf(); return ss.str();
}

static void print_hex_trunc(const std::string& title, const std::vector<uint8_t>& data, size_t maxBytes = 8) {
    std::cout << title << " (" << data.size() << " bytes): ";
    size_t toShow = std::min(maxBytes, data.size());
    for (size_t i = 0; i < toShow; ++i) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << (i + 1 < toShow ? " " : "");
    }
    if (data.size() > toShow) std::cout << " ...";
    std::cout << std::dec << std::endl;
}

int main(int argc, char** argv) {
    try {
        CryptoGlobalInit wolfSslGlobal;
        std::cout << "--- ArborKey Crypto Demo ---\n\n";

        json vaultData;
        vaultData["username"] = "test_user";
        vaultData["password"] = "a_very_secret_password_!@#$";
        vaultData["notes"] = "This demonstrates AES-GCM + Ed25519 signature + JSON storage.";

        std::string vaultString = vaultData.dump();
        std::vector<uint8_t> vaultVec(vaultString.begin(), vaultString.end());
        CryptoUtils::print_hex("Vault (raw) preview", vaultVec);

        std::cout << "\n--- Password-based encryption flow ---\n";
        std::string password = "MySuperStrongPassword123";

        PbkdfParams pbkdfParams;
        pbkdfParams.salt = CryptoUtils::genSalt();
        pbkdfParams.iterations = 4096;
        pbkdfParams.keySize = 32;

        std::vector<uint8_t> masterKey = CryptoUtils::deriveKeyFromPassword(password, pbkdfParams);
        std::vector<uint8_t> encKey = CryptoUtils::subKey(masterKey, "vault-encryption", 32);

        print_hex_trunc("Derived master key (truncated)", masterKey);
        print_hex_trunc("Derived encryption key (truncated)", encKey);

        MetaData meta("User Vault Data - password flow");
        EncryptedPacket packet = CryptoUtils::encryptData(vaultVec, encKey, meta);
        packet.pbkdfParams = std::make_unique<PbkdfParams>(pbkdfParams);

        auto signKeyPair = CryptoUtils::genSignKeyPair();
        auto signPubKey = CryptoUtils::exportSignPublicKey(*signKeyPair);

        json wrapper;
        wrapper["encryptedPackage"] = packet;
        std::string metaStr = wrapper["encryptedPackage"]["metadata"].dump();
        std::string cipherB64 = wrapper["encryptedPackage"]["cipherText"].get<std::string>();

        std::vector<uint8_t> toSign(metaStr.begin(), metaStr.end());
        toSign.insert(toSign.end(), cipherB64.begin(), cipherB64.end());

        std::vector<uint8_t> toSignHash = CryptoUtils::calculateHash(toSign);
        std::vector<uint8_t> signature = CryptoUtils::genSignature(toSignHash, *signKeyPair);

        wrapper["signature"] = Base64::encode(signature);
        wrapper["signerPubKey"] = Base64::encode(signPubKey);

        std::string finalJsonPayload = wrapper.dump(2);
        std::cout << "\nFinal JSON payload (password flow) preview:\n";
        std::cout << finalJsonPayload.substr(0, 1024) << (finalJsonPayload.size() > 1024 ? "\n... (truncated)\n" : "\n");

        const std::string path = "arborkey_payload_password.json";
        save_json_to_file(path, finalJsonPayload);
        std::cout << "Saved encrypted package to: " << path << "\n";

        CryptoUtils::secureZero(masterKey);
        CryptoUtils::secureZero(encKey);
        CryptoUtils::secureZero(toSignHash);

        std::cout << "\n--- Load -> Verify -> Decrypt (password flow) ---\n";
        std::string loaded = load_json_from_file(path);
        json received = json::parse(loaded);

        std::vector<uint8_t> receivedSig = Base64::decode(received["signature"].get<std::string>());
        std::vector<uint8_t> receivedPubKey = Base64::decode(received["signerPubKey"].get<std::string>());

        std::string recvMetaStr = received["encryptedPackage"]["metadata"].dump();
        std::string recvCipherB64 = received["encryptedPackage"]["cipherText"].get<std::string>();
        std::vector<uint8_t> verifyData(recvMetaStr.begin(), recvMetaStr.end());
        verifyData.insert(verifyData.end(), recvCipherB64.begin(), recvCipherB64.end());

        std::vector<uint8_t> verifyHash = CryptoUtils::calculateHash(verifyData);
        bool verified = CryptoUtils::verifySignature(verifyHash, receivedSig, receivedPubKey);
        std::cout << "Signature verification result: " << (verified ? "OK" : "FAILED") << std::endl;
        if (!verified) throw std::runtime_error("Signature verification failed for the password flow.");

        EncryptedPacket recvPacket = received["encryptedPackage"].get<EncryptedPacket>();
        if (!recvPacket.pbkdfParams) throw std::runtime_error("Missing PBKDF params in received packet.");

        std::vector<uint8_t> reDerivedMaster = CryptoUtils::deriveKeyFromPassword(password, *recvPacket.pbkdfParams);
        std::vector<uint8_t> reDerivedEnc = CryptoUtils::subKey(reDerivedMaster, "vault-encryption", 32);

        std::vector<uint8_t> decrypted = CryptoUtils::decryptData(recvPacket, reDerivedEnc);
        json decryptedJson = json::parse(std::string(decrypted.begin(), decrypted.end()));
        std::cout << "Decrypted JSON (password flow):\n" << decryptedJson.dump(2) << "\n";

        CryptoUtils::secureZero(reDerivedMaster);
        CryptoUtils::secureZero(reDerivedEnc);
        CryptoUtils::secureZero(decrypted);
        CryptoUtils::secureZero(vaultVec);

        std::cout << "\n--- Optional: Curve25519 DH-derived key demo ---\n";
        auto alice = CryptoUtils::genDhKeyPair();
        auto bob = CryptoUtils::genDhKeyPair();

        print_hex_trunc("Alice public (trunc)", alice->publicKey, 8);
        print_hex_trunc("Bob   public (trunc)", bob->publicKey, 8);

        std::vector<uint8_t> s1 = CryptoUtils::genSharedSecret(*alice, bob->publicKey);
        std::vector<uint8_t> s2 = CryptoUtils::genSharedSecret(*bob, alice->publicKey);

        if (!CryptoUtils::verifyHash(s1, s2)) throw std::runtime_error("DH derived secrets do not match!");
        std::cout << "DH shared secret: match OK\n";

        std::vector<uint8_t> dhEncKey = CryptoUtils::subKey(s1, "dh-vault-encryption", 32);
        print_hex_trunc("DH-derived enc key (trunc)", dhEncKey);

        std::string dhMsg = "Message protected by DH-derived key";
        std::vector<uint8_t> dhPlain(dhMsg.begin(), dhMsg.end());
        EncryptedPacket dhPacket = CryptoUtils::encryptData(dhPlain, dhEncKey, MetaData("dh-demo"));
        std::vector<uint8_t> dhDecrypted = CryptoUtils::decryptData(dhPacket, dhEncKey);
        std::cout << "DH decrypted message: " << std::string(dhDecrypted.begin(), dhDecrypted.end()) << "\n";

        CryptoUtils::secureZero(s1);
        CryptoUtils::secureZero(s2);
        CryptoUtils::secureZero(dhEncKey);
        CryptoUtils::secureZero(dhPlain);
        CryptoUtils::secureZero(dhDecrypted);

        std::cout << "\n--- Demo complete ---\n";
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
