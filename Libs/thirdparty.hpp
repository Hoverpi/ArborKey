#pragma once

#ifndef THIRDPARTY_HPP
#define THIRDPARTY_HPP

#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <climits>
#include <cstdlib>
#include <fstream>
#include <unordered_map>
#include <termios.h>
#include <unistd.h>
#include <csignal>
#include <functional>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "json.hpp" // https://github.com/nlohmann/json

// WolfSSL Headers
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/misc.h>

// Use nlohmann::json for JSON operations
using json = nlohmann::ordered_json;
namespace fs = std::filesystem;
using std::string;

#endif