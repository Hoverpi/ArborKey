// #include "Libs/Shell.hpp"
#include "Libs/CryptoUtils.hpp"

int main() {
    /* Shell shell = Shell();
    shell.run(); */
    // Build a vault programmatically
    try {
        // Initialize crypto library (RAII)
        CryptoGlobalInit init;  

        // --- 1) Prepare master-key params & derive DMK from password
        MasterKey mk;
        mk.masterParams.iterations = 100000;
        mk.masterParams.keySize = 32;

        string password = "correct-horse-battery-staple";

        // generate raw salt and derive key
        std::vector<uint8_t> outSalt = CryptoUtils::genSalt(); // 16 bytes by default
        auto masterKey = CryptoUtils::calculateDerivedKey(password, mk, outSalt);
        std::cout << "Derived master key (" << masterKey.size() << " bytes)\n";

        // --- 2) Create & calculate subkey (HKDF with salt)
        SubKey sk;
        sk.subParams.hashType = "SHA512";
        sk.subParams.keySize = 32; // derive 32 byte subkey
        string info = "session-v1";

        CryptoUtils::calculateSubKey(masterKey, info, sk);
        std::cout << "SubKey calculated. Encrypted packet iv (base64): " << sk.ep.iv << "\n";

        // Persisted representation (example)
        Vault v;
        v.id = CryptoUtils::genVaultId();   // base64 string id
        v.username = "alice";
        v.mk = mk;
        v.sk = sk;

        // --- 3) Verify subkey now (should succeed)
        bool ok = CryptoUtils::verifySubKey(masterKey, sk, info);
        std::cout << "Initial subkey verification: " << (ok ? "OK" : "FAIL") << "\n";
        if (!ok) return 1;

        // --- 4) Encrypt an entry using the derived master key
        string sample = "github-username: alice\npassword: verysecret";
        std::vector<uint8_t> plain(sample.begin(), sample.end());
        string aadEntry = "{\"vault_id\":\"" + v.id + "\",\"entry_id\":\"1\",\"user\":\"" + v.username + "\"}";

        EncryptedPacket epEntry = CryptoUtils::encryptData(plain, masterKey, aadEntry);

        // Create entry and append to vault
        Entry e = CryptoUtils::createEntry(string("1"), string("github"), string("https://github.com"), epEntry);
        v.entries.push_back(e);

        // --- SAVE/LOAD to disk (added) ---
        // Save vault to disk
        try {
            CryptoUtils::toFile(v, "vault.json");
            std::cout << "Vault written to vault.json\n";
        } catch (const std::exception& ex) {
            std::cerr << "Error writing vault: " << ex.what() << "\n";
        }

        // Read vault back
        try {
            Vault loaded = CryptoUtils::fromFile("vault.json");
            std::cout << "Loaded vault: id=" << loaded.id << " user=" << loaded.username << "\n";
        } catch (const std::exception& ex) {
            std::cerr << "Error reading vault: " << ex.what() << "\n";
        }

        // --- 5) Serialize vault to JSON
        json j = CryptoUtils::vaultToJson(v);
        std::cout << "\nVault JSON (pretty):\n" << j.dump(2) << "\n";

        // --- 6) Deserialize back from JSON
        Vault v2 = CryptoUtils::vaultFromJson(j);
        std::cout << "\nDeserialized vault id: " << v2.id << ", user: " << v2.username << "\n";

        // --- 7) Re-verify subkey with deserialized data
        bool ok2 = CryptoUtils::verifySubKey(masterKey, v2.sk, info);
        std::cout << "Verification after JSON round-trip: " << (ok2 ? "OK" : "FAIL") << "\n";
        if (!ok2) return 2;

        // --- 8) Decrypt entry from deserialized vault
        if (!v2.entries.empty()) {
            std::vector<uint8_t> recovered = CryptoUtils::decryptData(v2.entries[0].ep, masterKey);
            string recoveredStr(recovered.begin(), recovered.end());
            std::cout << "\nRecovered entry plaintext:\n" << recoveredStr << "\n";
        } else {
            std::cout << "No entries found in deserialized vault\n";
        }

        // --- 9) Cleanup sensitive vectors
        if (!masterKey.empty()) CryptoUtils::secureZero(masterKey.data(), masterKey.size());

        std::cout << "\nTEST completed successfully.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << "\n";
        return 99;
    }

    return 0;
}
