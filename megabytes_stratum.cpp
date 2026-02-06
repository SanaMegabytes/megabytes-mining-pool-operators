
// compile :
// cd megabytes/src
// g++ -std=c++17 megabytes_stratum.cpp -I src -I . -I crypto crypto/libmegabytes_consensus_a-groestl.o crypto/libmegabytes_consensus_a-kawpow.o .libs/libmegabytesconsensus.a libmegabytes_util.a -lcurl -pthread -o megabytes_stratum
// Usage: ./megabytes_stratum 3333 http://127.0.0.1:8332 deamonRpcUser deamonRpcPassword
//
// Notes:
// - TEST stratum only (not secure / not optimized).
// - One client per TCP connection (multiple connections supported).
// - Supports DAG+MNS+MHIS "classic" Stratum with KAWPOW RVN-style for kawpowminer.
// - For KAWPOW, this stratum can intentionally increase difficulty (see KAWPOW_DIFF_FACTOR).

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// POSIX sockets
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// libcurl
#include <curl/curl.h>

// nlohmann::json
#include "json.hpp"

// Megabytes / Core headers
#include "arith_uint256.h"
#include "consensus/merkle.h"
#include "crypto/common.h"
#include "crypto/hashgroestl.h"
#include "crypto/kawpow.h"
#include "crypto/kheavyhash.h"
#include "crypto/scrypt.h"
#include "crypto/sha256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "util/strencodings.h"
#include "version.h"

// Keccak (ethash)
#include <crypto/ethash/include/ethash/keccak.hpp>

using json = nlohmann::json;

// -----------------------------------------------------------------------------
// Translation stub (Core-style code expects this symbol).
// -----------------------------------------------------------------------------
std::function<std::string(const char*)> G_TRANSLATION_FUN =
    [](const char* psz) { return std::string(psz ? psz : ""); };

// -----------------------------------------------------------------------------
// Config: intentionally increase KAWPOW difficulty sent to miner.
// 1 = same as daemon, 16/64/256 = harder (fewer shares, fewer blocks).
// regtest no stale share tests, so can use higher values for testing.
// -----------------------------------------------------------------------------
static constexpr uint32_t KAWPOW_DIFF_FACTOR = 64000000;

// -----------------------------------------------------------------------------
// Algo enum (no Equihash).
// -----------------------------------------------------------------------------
enum class AlgoType {
    GROESTL,
    SHA256D,
    SCRYPT,
    KHEAVY80,
    KAWPOW,
};

static AlgoType ParseAlgo(std::string name) {
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    // normalize: remove spaces/dashes/underscores
    name.erase(std::remove_if(name.begin(), name.end(), [](unsigned char c) {
                   return c == ' ' || c == '-' || c == '_';
               }),
               name.end());

    if (name == "groestl" || name == "groestlsha2" || name == "groestlcoin")
        return AlgoType::GROESTL;
    if (name == "sha256d" || name == "sha256" || name == "sha256dt" || name == "doublesha256")
        return AlgoType::SHA256D;
    if (name == "scrypt" || name == "scryptn")
        return AlgoType::SCRYPT;
    if (name == "kheavy80" || name == "kheavyhash" || name == "kheavy")
        return AlgoType::KHEAVY80;
    if (name == "kawpow" || name == "progpow" || name == "rvn")
        return AlgoType::KAWPOW;

    return AlgoType::GROESTL;
}

static std::string AlgoToGbtName(AlgoType algo) {
    switch (algo) {
        case AlgoType::GROESTL:  return "groestlsha2";
        case AlgoType::SHA256D:  return "sha256d";
        case AlgoType::SCRYPT:   return "scrypt";
        case AlgoType::KHEAVY80: return "kheavy80";
        case AlgoType::KAWPOW:   return "kawpow";
    }
    return "groestlsha2";
}

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------
static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static std::string Strip0x(const std::string& s) {
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return s.substr(2);
    return s;
}

static std::string BytesToHex(const std::vector<uint8_t>& data) {
    static const char* hexmap = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t c : data) {
        out.push_back(hexmap[(c >> 4) & 0xF]);
        out.push_back(hexmap[c & 0xF]);
    }
    return out;
}

static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const std::string byteStr = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteStr.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

static std::string VarIntToHex(uint64_t v) {
    std::vector<uint8_t> out;
    if (v < 0xfd) {
        out.push_back((uint8_t)v);
    } else if (v <= 0xffff) {
        out.push_back(0xfd);
        out.push_back((uint8_t)(v & 0xff));
        out.push_back((uint8_t)((v >> 8) & 0xff));
    } else if (v <= 0xffffffffULL) {
        out.push_back(0xfe);
        for (int i = 0; i < 4; ++i) out.push_back((uint8_t)((v >> (8 * i)) & 0xff));
    } else {
        out.push_back(0xff);
        for (int i = 0; i < 8; ++i) out.push_back((uint8_t)((v >> (8 * i)) & 0xff));
    }
    return BytesToHex(out);
}

static std::vector<uint8_t> U32ToLE(uint32_t v) {
    return { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
}

// Keccak(header80) => 64 hex chars
static std::string KeccakHeader80Hex(const std::vector<uint8_t>& header80) {
    const auto k = ethash::keccak256(header80.data(), header80.size());
    return BytesToHex(std::vector<uint8_t>(k.bytes, k.bytes + 32));
}

static std::string HexTargetFromArith(const arith_uint256& t) {
    const uint256 u = ArithToUint256(t);   // <-- returns by value in your tree
    return ToLower(u.ToString());          // big-endian hex
}

// Make target smaller => harder difficulty.
// factor=64 means target = target/64 (harder).
static std::string MakeHarderTarget(const std::string& daemonTargetHex, uint32_t factor) {
    if (factor <= 1) return daemonTargetHex;
    arith_uint256 t;
    t.SetHex(daemonTargetHex);
    t /= factor;
    if (t == 0) t = 1;
    return HexTargetFromArith(t);
}

// Extract algo override from miner password (classic stratum).
static std::optional<std::string> ExtractAlgoFromMinerPassword(std::string pass) {
    pass = ToLower(pass);

    auto is_sep = [](char c) { return c == ',' || c == ';' || c == ' ' || c == '\t'; };

    size_t i = 0;
    while (i < pass.size()) {
        while (i < pass.size() && is_sep(pass[i])) i++;
        size_t j = i;
        while (j < pass.size() && !is_sep(pass[j])) j++;
        if (j > i) {
            std::string token = pass.substr(i, j - i); // e.g. "algo=kawpow"
            const std::string key = "algo=";
            if (token.rfind(key, 0) == 0 && token.size() > key.size())
                return token.substr(key.size());
        }
        i = j;
    }
    return std::nullopt;
}

// -----------------------------------------------------------------------------
// Local PoW for classic algos (non-KAWPOW).
// -----------------------------------------------------------------------------
static uint256 ComputePowHashForHeader(const std::vector<uint8_t>& header, AlgoType algo) {
    const unsigned char* pbegin = header.data();
    const unsigned char* pend   = pbegin + header.size();

    switch (algo) {
        case AlgoType::SHA256D: {
            uint8_t h1[32];
            uint8_t h2[32];

            CSHA256 sha1;
            sha1.Write(pbegin, header.size());
            sha1.Finalize(h1);

            CSHA256 sha2;
            sha2.Write(h1, 32);
            sha2.Finalize(h2);

            uint256 out;
            out.SetHex(BytesToHex(std::vector<uint8_t>(h2, h2 + 32)));
            return out;
        }
        case AlgoType::SCRYPT: {
            uint256 thash;
            scrypt_1024_1_1_256(reinterpret_cast<const char*>(pbegin),
                                reinterpret_cast<char*>(thash.data()));
            return thash;
        }
        case AlgoType::GROESTL:
            return HashGroestl(pbegin, pend);
        case AlgoType::KHEAVY80:
            return HashKHeavy(pbegin, pend);
        case AlgoType::KAWPOW:
            // KAWPOW is handled in its own path.
            return uint256();
    }
    return uint256();
}

// -----------------------------------------------------------------------------
// Merkle root from tx hex list.
// -----------------------------------------------------------------------------
static uint256 ComputeMerkleRootFromTxs(const std::vector<std::string>& txs_hex) {
    std::vector<uint256> hashes;
    hashes.reserve(txs_hex.size());

    for (const auto& tx_hex : txs_hex) {
        std::vector<unsigned char> tx_bytes = ParseHex(tx_hex);
        CDataStream ss(tx_bytes, SER_NETWORK, PROTOCOL_VERSION);

        CMutableTransaction mtx;
        ss >> mtx;

        CTransaction tx(mtx);
        hashes.push_back(tx.GetHash());
    }

    bool mutated = false;
    return ComputeMerkleRoot(hashes, &mutated);
}

// -----------------------------------------------------------------------------
// Minimal RPC client (curl).
// -----------------------------------------------------------------------------
struct RpcClient {
    std::string url;
    std::string userpass; // "user:pass"

    RpcClient(const std::string& u, const std::string& up) : url(u), userpass(up) {}

    static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
        auto* s = static_cast<std::string*>(userdata);
        s->append(ptr, size * nmemb);
        return size * nmemb;
    }

    json call(const std::string& method, const json& params) {
        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("curl_easy_init failed");

        json req;
        req["jsonrpc"] = "1.0";
        req["id"]      = "stratum";
        req["method"]  = method;
        req["params"]  = params;

        const std::string reqStr = req.dump();
        std::string respStr;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, reqStr.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, reqStr.size());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respStr);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, userpass.c_str());
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            throw std::runtime_error(std::string("curl_easy_perform failed: ") + curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        json resp = json::parse(respStr);
        if (!resp["error"].is_null()) {
            throw std::runtime_error("RPC error: " + resp["error"].dump());
        }
        return resp["result"];
    }
};

// -----------------------------------------------------------------------------
// Coinbase splitting: build coinb1/coinb2 using coinbasetxn + placeholder extranonces.
// -----------------------------------------------------------------------------
struct StratumCoinbaseTemplate {
    std::string coinb1;
    std::string coinb2;
};

static StratumCoinbaseTemplate BuildStratumCoinbaseTemplate(
    const json& gbt,
    const std::string& extranonce1_hex,
    int extranonce2_size)
{
    StratumCoinbaseTemplate tpl;

    const int ex1_bytes = (int)extranonce1_hex.size() / 2;
    const int ex2_bytes = extranonce2_size;
    const int extra_bytes = ex1_bytes + ex2_bytes;

    // Use a UNIQUE placeholder pattern to avoid accidental matches.
    // Repeat 0xFA,0xBF,... sequence.
    static const uint8_t kPat[] = {0xFA, 0xBF, 0xFA, 0xBF, 0xFA, 0xBF, 0xFA, 0xBF};
    std::vector<unsigned char> extra_placeholder;
    extra_placeholder.reserve(extra_bytes);
    for (int i = 0; i < extra_bytes; ++i) {
        extra_placeholder.push_back(kPat[i % (int)sizeof(kPat)]);
    }

    // Require coinbasetxn.data from daemon (recommended for DAG/MNS correctness)
    if (!(gbt.contains("coinbasetxn") && gbt["coinbasetxn"].is_object() &&
          gbt["coinbasetxn"].contains("data") && gbt["coinbasetxn"]["data"].is_string())) {
        // If you truly want fallback, keep your old fallback block here.
        // But for a pool operator doc: better to fail hard.
        throw std::runtime_error("coinbasetxn.data missing from getblocktemplate");
    }

    const std::string cb_hex = gbt["coinbasetxn"]["data"].get<std::string>();

    // Decode coinbase tx
    std::vector<unsigned char> tx_bytes_orig = ParseHex(cb_hex);
    CDataStream ss(tx_bytes_orig, SER_NETWORK, PROTOCOL_VERSION);

    CMutableTransaction mtx;
    ss >> mtx;

    if (mtx.vin.empty()) {
        throw std::runtime_error("coinbase has no vin");
    }

    // Append placeholder to scriptSig (ONLY place we modify)
    mtx.vin[0].scriptSig << extra_placeholder;

    // Serialize modified tx (SegWit-aware serialization is handled by Core)
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << mtx;

    std::vector<unsigned char> tx_bytes;
    tx_bytes.reserve(ss2.size());
    for (auto b : ss2) tx_bytes.push_back((unsigned char)b);

    // Find the placeholder in the FULL serialized tx bytes
    auto it = std::search(tx_bytes.begin(), tx_bytes.end(),
                          extra_placeholder.begin(), extra_placeholder.end());
    if (it == tx_bytes.end()) {
        throw std::runtime_error("extranonce placeholder not found in serialized coinbase");
    }

    const size_t start = (size_t)std::distance(tx_bytes.begin(), it);
    const size_t end   = start + (size_t)extra_bytes;

    if (end > tx_bytes.size()) {
        throw std::runtime_error("placeholder exceeds serialized tx size");
    }

    std::vector<uint8_t> b1(tx_bytes.begin(), tx_bytes.begin() + start);
    std::vector<uint8_t> b2(tx_bytes.begin() + end, tx_bytes.end());

    tpl.coinb1 = BytesToHex(b1);
    tpl.coinb2 = BytesToHex(b2);
    return tpl;
}


// -----------------------------------------------------------------------------
// Stratum session (one TCP connection).
// -----------------------------------------------------------------------------
struct StratumSession {
    int client_fd;
    RpcClient& rpc;

    std::atomic<bool> running{true};

    // Protocol detection
    bool is_kawpow_stratum = false;

    // Current algo selected by pool / password override
    AlgoType current_algo = AlgoType::GROESTL;

    // Extranonce
    std::string extranonce1 = "00000001"; // 4 bytes hex
    int extranonce2_size = 4;             // bytes

    // Job state (latest template)
    uint64_t job_counter = 0;
    std::string current_job_id;

    uint32_t job_version = 0;
    uint32_t job_height  = 0;
    uint32_t job_curtime = 0;
    uint32_t job_mintime = 0;

    std::string job_prevhash;
    std::string job_bits;
    std::string job_target_daemon; // from daemon
    std::string job_target_miner;  // possibly harder (KAWPOW)

    std::string job_coinb1;
    std::string job_coinb2;
    std::vector<std::string> job_txs_no_coinbase_hex;
    json last_gbt;

    // KAWPOW cache for validation (so we can validate submits even after new GBT)
    struct KawpowJob {
        std::string job_id;

        uint32_t height = 0;
        uint32_t version = 0;
        uint32_t ntime = 0;
        uint32_t bits = 0;

        std::string prevhash;
        std::string header_hash; // keccak(header80)
        std::string seed_hash;

        std::string coinb1, coinb2;
        std::vector<std::string> txs;

        std::string extranonce1;
        std::string extranonce2_fixed; // we keep it fixed in this test stratum

        std::string target_daemon;
        std::string target_miner; // harder

        bool solved = false;
    };

    uint64_t kawpow_job_seq = 0;
    std::string kawpow_active_job_id;
    std::vector<KawpowJob> kawpow_jobs; // small cache

    explicit StratumSession(int fd, RpcClient& r) : client_fd(fd), rpc(r) {}
    ~StratumSession() {
        if (client_fd >= 0) close(client_fd);
    }

    static std::string Hex8(uint64_t v) {
        char buf[9];
        snprintf(buf, sizeof(buf), "%08llx", (unsigned long long)(v & 0xffffffffULL));
        return std::string(buf);
    }

    // Read one JSON line (newline-delimited).
    std::optional<std::string> read_line() {
        std::string line;
        char c;
        while (true) {
            ssize_t n = recv(client_fd, &c, 1, 0);
            if (n <= 0) return std::nullopt;
            if (c == '\n') break;
            if (c != '\r') line.push_back(c);
        }
        return line;
    }

    void send_json(const json& j) {
        std::string s = j.dump();
        s.push_back('\n');
        (void)send(client_fd, s.c_str(), s.size(), 0);
        std::cout << "[-> CLIENT] " << s;
    }

    // Classic subscribe response
    void send_subscribe_response(int id) {
        json resp;
        resp["id"] = id;
        resp["error"] = nullptr;

        json arr0 = json::array();
        arr0.push_back(json::array({"mining.set_difficulty", "bf"}));
        arr0.push_back(json::array({"mining.notify", "bf"}));

        resp["result"] = json::array();
        resp["result"].push_back(arr0);
        resp["result"].push_back(extranonce1);
        resp["result"].push_back(extranonce2_size);

        send_json(resp);
    }

    // KAWPOW miner subscribe response (kawpowminer expects ["extranonce1","04"]).
    void send_subscribe_response_kawpow(int id) {
        json resp;
        resp["id"] = id;
        resp["error"] = nullptr;

        std::stringstream ss;
        ss << std::hex << std::setw(2) << std::setfill('0') << extranonce2_size; // "04"
        const std::string ex2_hex = ss.str();

        resp["result"] = json::array({ extranonce1, ex2_hex });

        send_json(resp);

        std::cout << "[INFO] kawpow subscribe: extranonce1=" << extranonce1
                  << " extranonce2_size=" << ex2_hex << "\n";
    }

    void send_authorize_response(int id, bool ok = true) {
        json resp;
        resp["id"] = id;
        resp["error"] = nullptr;
        resp["result"] = ok;
        send_json(resp);
    }

    // KAWPOW target setter (uses job_target_miner when available).
    void send_set_target_kawpow() {
        const std::string& t = (!job_target_miner.empty()) ? job_target_miner : job_target_daemon;
        if (t.empty()) {
            std::cerr << "[WARN] send_set_target_kawpow: target is empty\n";
            return;
        }

        json msg;
        msg["id"] = nullptr;
        msg["method"] = "mining.set_target";
        msg["params"] = json::array({ t });
        send_json(msg);

        std::cout << "[INFO] mining.set_target -> " << t << "\n";
    }

    // Classic set_difficulty (kept simple)
    void send_set_difficulty_classic(double diff = 1.0) {
        json setdiff;
        setdiff["id"] = nullptr;
        setdiff["method"] = "mining.set_difficulty";
        setdiff["params"] = json::array({ diff });
        send_json(setdiff);
    }

    // Build classic header (80 bytes): version | prev | merkle | time | bits | nonce
    std::vector<uint8_t> build_classic_header80(uint32_t ntime, uint32_t nonce, const std::string& merkle_root_hex) {
        std::vector<uint8_t> header;
        header.reserve(80);

        auto ver = U32ToLE(job_version);
        header.insert(header.end(), ver.begin(), ver.end());

        auto prev = HexToBytes(job_prevhash);
        std::reverse(prev.begin(), prev.end());
        header.insert(header.end(), prev.begin(), prev.end());

        auto merkle = HexToBytes(merkle_root_hex);
        std::reverse(merkle.begin(), merkle.end());
        header.insert(header.end(), merkle.begin(), merkle.end());

        auto nt = U32ToLE(ntime);
        header.insert(header.end(), nt.begin(), nt.end());

        uint32_t bits = (uint32_t)strtoul(job_bits.c_str(), nullptr, 16);
        auto bt = U32ToLE(bits);
        header.insert(header.end(), bt.begin(), bt.end());

        auto nn = U32ToLE(nonce);
        header.insert(header.end(), nn.begin(), nn.end());

        assert(header.size() == 80);
        return header;
    }

    // Submit a classic block candidate (raw header80 + txs)
    void submit_block_candidate_classic(const std::vector<uint8_t>& header80,
                                        const std::string& full_coinbase_hex)
    {
        std::string block_hex = BytesToHex(header80);

        std::vector<std::string> all_txs;
        all_txs.reserve(1 + job_txs_no_coinbase_hex.size());
        all_txs.push_back(full_coinbase_hex);
        all_txs.insert(all_txs.end(), job_txs_no_coinbase_hex.begin(), job_txs_no_coinbase_hex.end());

        block_hex += VarIntToHex(all_txs.size());
        for (const auto& tx_hex : all_txs) block_hex += tx_hex;

        try {
            json params = json::array();
            params.push_back(block_hex);
            json res = rpc.call("submitblock", params);
            std::cout << ">>> submitblock result: " << res.dump() << "\n";
        } catch (const std::exception& e) {
            std::cout << "!!! submitblock error: " << e.what() << "\n";
        }
    }

    // Submit KAWPOW block by serializing CBlock (matches daemon serialization)
    bool submit_block_candidate_kawpow_ser(const CBlockHeader& hdr_in,
                                           const std::string& full_coinbase_hex,
                                           const uint256& mix_out,
                                           const std::vector<std::string>& txs_no_coinbase_hex)
    {
        try {
            CBlock block;
            static_cast<CBlockHeader&>(block) = hdr_in;

            // Ensure correct KAWPOW fields
            block.nHeight  = hdr_in.nHeight;
            block.nNonce64 = hdr_in.nNonce64;
            block.nNonce   = 0;        // not used in your KAWPOW layout
            block.mix_hash = mix_out;  // mix used by daemon validation

            auto decode_tx = [](const std::string& hex) -> CTransactionRef {
                std::vector<unsigned char> bytes = ParseHex(hex);
                CDataStream ss(bytes, SER_NETWORK, PROTOCOL_VERSION);
                CMutableTransaction mtx;
                ss >> mtx;
                return MakeTransactionRef(std::move(mtx));
            };

            block.vtx.clear();
            block.vtx.emplace_back(decode_tx(full_coinbase_hex));
            for (const auto& tx_hex : txs_no_coinbase_hex) block.vtx.emplace_back(decode_tx(tx_hex));

            // Debug header size (your code expects 120 bytes)
            CDataStream ssHdr(SER_NETWORK, PROTOCOL_VERSION);
            ssHdr << static_cast<const CBlockHeader&>(block);
            std::cout << "[KAWPOW SER] header_bytes=" << ssHdr.size() << " (expect 120)\n";

            CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
            ssBlock << block;
            const std::string block_hex = HexStr(ssBlock);

            json params = json::array();
            params.push_back(block_hex);

            json res = rpc.call("submitblock", params);
            std::cout << ">>> submitblock (KAWPOW SER) result: " << res.dump() << "\n";

            // Bitcoin-style: null means accepted
            return res.is_null();
        } catch (const std::exception& e) {
            std::cout << "!!! submitblock (KAWPOW SER) error: " << e.what() << "\n";
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Send a new job (classic or KAWPOW).
    // -------------------------------------------------------------------------
    void send_job_notify(bool clean_jobs) {
        json params = json::array();
        json tmpl_param;

        tmpl_param["rules"] = json::array({"segwit"});
        tmpl_param["capabilities"] = json::array({"proposal", "coinbasetxn"});

        const std::string gbt_algo_name = AlgoToGbtName(current_algo);
        tmpl_param["algo"] = gbt_algo_name;
        params.push_back(tmpl_param);

        std::cout << "[GBT REQ] algo=" << gbt_algo_name
                  << " is_kawpow_stratum=" << (is_kawpow_stratum ? "true" : "false")
                  << " current_algo=" << (int)current_algo
                  << "\n";

        json gbt = rpc.call("getblocktemplate", params);
        last_gbt = gbt;

        job_prevhash = gbt.value("previousblockhash", "");
        job_bits     = gbt.value("bits", "");
        job_target_daemon = gbt.value("target", "");
        job_height   = gbt.value("height", 0);
        job_version  = gbt.value("version", 0);

        const int64_t gbt_curtime = gbt.value("curtime", 0);
        const int64_t gbt_mintime = gbt.value("mintime", 0);

        // Choose a safe time: >= mintime+1, >= curtime, >= now
        const int64_t now = (int64_t)std::time(nullptr);
        const int64_t chosen_time = std::max({ gbt_mintime + 1, gbt_curtime, now });

        job_curtime = (uint32_t)chosen_time;
        job_mintime = (uint32_t)std::max<int64_t>(gbt_mintime, 0);

        std::cout << "[JOB] raw curtime=" << gbt_curtime
                  << " mintime=" << gbt_mintime
                  << " used_curtime=" << job_curtime
                  << "\n";

        // Daemon may echo pow algo in pow_algo field
        const std::string pow_name = gbt.value("pow_algo", gbt_algo_name);
        const uint32_t verAlgo = (job_version >> 16) & 0xF;

        std::cout << "[JOB] version=0x" << std::hex << job_version << std::dec
                  << " algoNibble=" << verAlgo
                  << " pow_algo=" << pow_name
                  << "\n";

        current_algo = ParseAlgo(pow_name);

        // Transactions (excluding coinbase)
        job_txs_no_coinbase_hex.clear();
        if (gbt.contains("transactions") && gbt["transactions"].is_array()) {
            for (const auto& tx : gbt["transactions"]) {
                if (tx.contains("data") && tx["data"].is_string())
                    job_txs_no_coinbase_hex.push_back(tx["data"].get<std::string>());
            }
        }

        // Build coinb1/coinb2
        StratumCoinbaseTemplate ctpl = BuildStratumCoinbaseTemplate(gbt, extranonce1, extranonce2_size);
        job_coinb1 = ctpl.coinb1;
        job_coinb2 = ctpl.coinb2;

        std::cout << "[JOB] height=" << job_height
                  << " prevhash=" << job_prevhash
                  << " bits=" << job_bits
                  << " txs=" << (1 + job_txs_no_coinbase_hex.size())
                  << "\n";

        // If KAWPOW: compute harder miner target (optional)
        job_target_miner.clear();
        if (is_kawpow_stratum && current_algo == AlgoType::KAWPOW) {
            job_target_miner = MakeHarderTarget(job_target_daemon, KAWPOW_DIFF_FACTOR);
            if (KAWPOW_DIFF_FACTOR > 1) {
                std::cout << "[KAWPOW] diff factor=" << KAWPOW_DIFF_FACTOR
                          << " target_daemon=" << job_target_daemon
                          << " target_miner=" << job_target_miner
                          << "\n";
            }
        }

        // Dispatch
        if (is_kawpow_stratum && current_algo == AlgoType::KAWPOW) {
            send_set_target_kawpow();
            send_job_notify_kawpow(clean_jobs);
            return;
        }

        send_job_notify_classic(clean_jobs);
    }

    // -------------------------------------------------------------------------
    // Classic notify (BTC-like)
    // mining.notify params:
    // [job_id, prevhash, coinb1, coinb2, merkle_branches[], version, bits, ntime, clean]
    // -------------------------------------------------------------------------
    void send_job_notify_classic(bool clean_jobs) {
        job_counter++;
        std::stringstream ss_job;
        ss_job << std::hex << std::setw(8) << std::setfill('0') << job_counter;
        current_job_id = ss_job.str();

        std::stringstream ss_version, ss_ntime;
        ss_version << std::hex << std::setw(8) << std::setfill('0') << job_version;
        ss_ntime   << std::hex << std::setw(8) << std::setfill('0') << job_curtime;

        const std::string version_hex = ss_version.str();
        const std::string ntime_hex   = ss_ntime.str();

        json notif;
        notif["id"] = nullptr;
        notif["method"] = "mining.notify";
        notif["params"] = json::array();

        notif["params"].push_back(current_job_id);
        notif["params"].push_back(job_prevhash);
        notif["params"].push_back(job_coinb1);
        notif["params"].push_back(job_coinb2);
        notif["params"].push_back(json::array()); // merkle branches
        notif["params"].push_back(version_hex);
        notif["params"].push_back(job_bits);
        notif["params"].push_back(ntime_hex);
        notif["params"].push_back(clean_jobs);

        send_json(notif);
        send_set_difficulty_classic(1.0);
    }

    // -------------------------------------------------------------------------
    // KAWPOW notify (RVN-style for kawpowminer):
    // mining.notify params:
    // [job_id, header_hash, seed_hash, target, clean_jobs, height, bits_u32]
    // -------------------------------------------------------------------------
    void send_job_notify_kawpow(bool clean_jobs) {
        // Keep extranonce2 fixed for test stratum (must match notify <-> submit reconstruction).
        const std::string extranonce2 = "00000000";
        const std::string full_coinbase_hex = job_coinb1 + extranonce1 + extranonce2 + job_coinb2;

        // Merkle root for this coinbase + gbt txs
        std::vector<std::string> txs_for_merkle;
        txs_for_merkle.reserve(1 + job_txs_no_coinbase_hex.size());
        txs_for_merkle.push_back(full_coinbase_hex);
        txs_for_merkle.insert(txs_for_merkle.end(),
                              job_txs_no_coinbase_hex.begin(),
                              job_txs_no_coinbase_hex.end());

        const uint256 merkle_root = ComputeMerkleRootFromTxs(txs_for_merkle);

        // Build your daemon's KAWPOW header80 layout:
        // [version 4 LE][prev 32 LE][merkle 32 LE][time 4 LE][bits 4 LE][height 4 LE]
        std::vector<uint8_t> header80;
        header80.reserve(80);

        // version
        {
            auto v = U32ToLE((uint32_t)job_version);
            header80.insert(header80.end(), v.begin(), v.end());
        }

        // prev (uint256 hex -> bytes reversed to LE)
        {
            uint256 prevU;
            prevU.SetHex(job_prevhash);
            auto prev = HexToBytes(prevU.ToString());
            std::reverse(prev.begin(), prev.end());
            header80.insert(header80.end(), prev.begin(), prev.end());
        }

        // merkle (same)
        {
            auto mr = HexToBytes(merkle_root.ToString());
            std::reverse(mr.begin(), mr.end());
            header80.insert(header80.end(), mr.begin(), mr.end());
        }

        // time, bits, height
        {
            auto t = U32ToLE(job_curtime);
            header80.insert(header80.end(), t.begin(), t.end());
        }
        {
            uint32_t bits_u32 = 0;
            try { bits_u32 = (uint32_t)std::stoul(job_bits, nullptr, 16); } catch (...) { bits_u32 = 0; }
            auto b = U32ToLE(bits_u32);
            header80.insert(header80.end(), b.begin(), b.end());
        }
        {
            auto h = U32ToLE((uint32_t)job_height);
            header80.insert(header80.end(), h.begin(), h.end());
        }

        if (header80.size() != 80) {
            std::cerr << "[KAWPOW] ERROR: header80 size=" << header80.size() << " expected 80\n";
            return;
        }

        const std::string header_hash = KeccakHeader80Hex(header80);

        // seedhash (if provided by daemon)
        std::string seed_hash(64, '0');
        if (last_gbt.contains("seedhash") && last_gbt["seedhash"].is_string()) {
            seed_hash = Strip0x(last_gbt["seedhash"].get<std::string>());
            seed_hash = ToLower(seed_hash);
        }

        // job id
        kawpow_job_seq++;
        current_job_id = Hex8(kawpow_job_seq);
        kawpow_active_job_id = current_job_id;

        // choose miner target: harder if configured
        const std::string target_to_send = (!job_target_miner.empty()) ? job_target_miner : job_target_daemon;

        json notif;
        notif["id"] = nullptr;
        notif["method"] = "mining.notify";
        notif["params"] = json::array();

        notif["params"].push_back(current_job_id);
        notif["params"].push_back(header_hash);
        notif["params"].push_back(seed_hash);
        notif["params"].push_back(target_to_send);
        notif["params"].push_back(clean_jobs);
        notif["params"].push_back((int)job_height);

        uint32_t bits_u32 = 0;
        try { bits_u32 = (uint32_t)std::stoul(job_bits, nullptr, 16); } catch (...) { bits_u32 = 0; }
        notif["params"].push_back((int)bits_u32);

        send_json(notif);

        std::cout << "[KAWPOW] notify job_id=" << current_job_id
                  << " clean=" << (clean_jobs ? "true" : "false")
                  << " height=" << job_height
                  << " header_hash=" << header_hash
                  << " seed=" << seed_hash
                  << " bits=" << job_bits
                  << " target_sent=" << target_to_send
                  << "\n";

        // Cache job for submit validation
        KawpowJob j;
        j.job_id = current_job_id;
        j.height = job_height;
        j.version = job_version;
        j.ntime = job_curtime;
        j.bits = bits_u32;
        j.prevhash = job_prevhash;
        j.header_hash = header_hash;
        j.seed_hash = seed_hash;
        j.coinb1 = job_coinb1;
        j.coinb2 = job_coinb2;
        j.txs = job_txs_no_coinbase_hex;
        j.extranonce1 = extranonce1;
        j.extranonce2_fixed = extranonce2;
        j.target_daemon = job_target_daemon;
        j.target_miner = target_to_send;
        j.solved = false;

        kawpow_jobs.insert(kawpow_jobs.begin(), std::move(j));
        if (kawpow_jobs.size() > 5) kawpow_jobs.pop_back();
    }

    // Find cached KAWPOW job
    KawpowJob* find_kawpow_job(const std::string& jid) {
        for (auto& j : kawpow_jobs)
            if (j.job_id == jid)
                return &j;
        return nullptr;
    }

    // -------------------------------------------------------------------------
    // Handle mining.submit
    // - KAWPOW RVN-style: [worker, job_id, nonce64hex, header_hash, mix_hash]
    // - Classic:          [worker, job_id, extranonce2, ntime, nonce]
    // -------------------------------------------------------------------------
    void handle_submit(const json& req) {
        const int id = req.value("id", 0);

        if (!req.contains("params") || !req["params"].is_array()) {
            json resp{{"id", id}, {"error", nullptr}, {"result", false}};
            send_json(resp);
            return;
        }

        const auto& p = req["params"];
        if (p.size() < 5) {
            json resp{{"id", id}, {"error", nullptr}, {"result", false}};
            send_json(resp);
            return;
        }

        // --------------------------
        // KAWPOW branch
        // --------------------------
        if (is_kawpow_stratum && current_algo == AlgoType::KAWPOW) {
            const std::string worker  = p[0].get<std::string>();
            const std::string job_id  = p[1].get<std::string>();
            const std::string nonce_s = p[2].get<std::string>();
            const std::string hdrhash = p[3].get<std::string>();
            const std::string mixhash = p[4].get<std::string>();

            // Reject stale job_id (miner pipeline after clean_jobs is normal)
            if (!kawpow_active_job_id.empty() && job_id != kawpow_active_job_id) {
                static uint64_t staleCount = 0;
                staleCount++;
                if ((staleCount % 50) == 1) {
                    std::cout << "[KAWPOW SUBMIT] REJECT stale job_id=" << job_id
                              << " active=" << kawpow_active_job_id
                              << " (stale_count=" << staleCount << ")\n";
                }
                json resp{{"id", id}, {"error", nullptr}, {"result", false}};
                send_json(resp);
                return;
            }

            KawpowJob* J = find_kawpow_job(job_id);
            if (!J) {
                std::cout << "[KAWPOW SUBMIT] REJECT unknown job_id=" << job_id << "\n";
                json resp{{"id", id}, {"error", nullptr}, {"result", false}};
                send_json(resp);
                return;
            }

            // Ignore late shares if job already produced an accepted block
            if (J->solved) {
                json resp{{"id", id}, {"error", nullptr}, {"result", true}};
                send_json(resp);
                return;
            }

            // Parse nonce64
            uint64_t nonce64 = 0;
            try {
                nonce64 = std::stoull(Strip0x(nonce_s), nullptr, 16);
            } catch (...) {
                std::cout << "[KAWPOW SUBMIT] invalid nonce: " << nonce_s << "\n";
                json resp{{"id", id}, {"error", nullptr}, {"result", false}};
                send_json(resp);
                return;
            }

            const std::string header_hex = ToLower(Strip0x(hdrhash));
            const std::string mix_hex    = ToLower(Strip0x(mixhash));

            // Rebuild full coinbase for THIS cached job (must match notify)
            const std::string full_coinbase_hex = J->coinb1 + J->extranonce1 + J->extranonce2_fixed + J->coinb2;

            // Merkle root for THIS cached job
            std::vector<std::string> txs_for_merkle;
            txs_for_merkle.reserve(1 + J->txs.size());
            txs_for_merkle.push_back(full_coinbase_hex);
            txs_for_merkle.insert(txs_for_merkle.end(), J->txs.begin(), J->txs.end());

            const uint256 merkle_root = ComputeMerkleRootFromTxs(txs_for_merkle);

            // Build header80 again and verify header_hash matches (prevents desync)
            std::vector<uint8_t> header80;
            header80.reserve(80);

            // version
            {
                auto v = U32ToLE((uint32_t)J->version);
                header80.insert(header80.end(), v.begin(), v.end());
            }
            // prev
            {
                uint256 prevU;
                prevU.SetHex(J->prevhash);
                auto prev = HexToBytes(prevU.ToString());
                std::reverse(prev.begin(), prev.end());
                header80.insert(header80.end(), prev.begin(), prev.end());
            }
            // merkle
            {
                auto mr = HexToBytes(merkle_root.ToString());
                std::reverse(mr.begin(), mr.end());
                header80.insert(header80.end(), mr.begin(), mr.end());
            }
            // time, bits, height
            {
                auto t = U32ToLE(J->ntime);
                header80.insert(header80.end(), t.begin(), t.end());
            }
            {
                auto b = U32ToLE(J->bits);
                header80.insert(header80.end(), b.begin(), b.end());
            }
            {
                auto h = U32ToLE(J->height);
                header80.insert(header80.end(), h.begin(), h.end());
            }

            const std::string expected_hdrhash = ToLower(KeccakHeader80Hex(header80));
            if (header_hex != expected_hdrhash) {
                std::cout << "[KAWPOW SUBMIT] REJECT bad headerhash: got=" << header_hex
                          << " expected=" << expected_hdrhash << "\n";
                json resp{{"id", id}, {"error", nullptr}, {"result", false}};
                send_json(resp);
                return;
            }

            // Build CBlockHeader for HashKawpow (your daemon uses nHeight in header80 and nNonce64 separately)
            CBlockHeader hdr;
            hdr.nVersion = (int32_t)J->version;
            hdr.hashPrevBlock.SetHex(J->prevhash);
            hdr.hashMerkleRoot = merkle_root;
            hdr.nTime = J->ntime;
            hdr.nBits = J->bits;
            hdr.nNonce = 0;
            hdr.nHeight = J->height;
            hdr.nNonce64 = nonce64;

            // Compute KAWPOW pow hash + mix_out
            uint256 mix_out;
            const uint256 pow_hash = HashKawpow(hdr, mix_out);

            // Compare against miner target (harder), so fewer shares
            uint256 target_miner;
            target_miner.SetHex(J->target_miner);

            const bool meets_target = UintToArith256(pow_hash) <= UintToArith256(target_miner);

            // Minimal logging (not too spammy)
            static uint64_t submitCount = 0;
            submitCount++;
            if ((submitCount % 25) == 1 || meets_target) {
                std::cout << "[KAWPOW SUBMIT] job_id=" << job_id
                          << " nonce=" << Strip0x(nonce_s)
                          << " meets_target=" << (meets_target ? "YES" : "NO")
                          << " pow_hash=" << pow_hash.ToString()
                          << " target_miner=" << target_miner.ToString()
                          << "\n";
            }

            bool accepted_by_daemon = false;

            // If it meets miner target, it also meets daemon target (since miner target is harder).
            if (meets_target) {
                hdr.mix_hash = mix_out; // daemon will validate mixhash against pow
                accepted_by_daemon = submit_block_candidate_kawpow_ser(hdr, full_coinbase_hex, mix_out, J->txs);
            }

            // Respond to miner: true only if meets our (harder) target
            {
                json resp;
                resp["id"] = id;
                resp["error"] = nullptr;
                resp["result"] = meets_target;
                send_json(resp);
            }

            std::cout << "[KAWPOW SUBMIT] meets_target=" << (meets_target ? "true" : "false")
                      << " daemon_accepted=" << (accepted_by_daemon ? "true" : "false")
                      << "\n";

            // IMPORTANT: only push a new job if daemon accepted the block
            if (accepted_by_daemon) {
                for (auto& jj : kawpow_jobs) jj.solved = true;

                std::cout << "[KAWPOW SUBMIT] BLOCK ACCEPTED: sending a fresh clean job\n";
                try {
                    send_job_notify(true); // SINGLE call (no double-send)
                } catch (const std::exception& e) {
                    std::cerr << "[WARN] Failed to send new job after accept: " << e.what() << "\n";
                }
            }

            return;
        }

        // --------------------------
        // Classic branch
        // --------------------------
        const std::string worker      = p[0].get<std::string>();
        const std::string job_id      = p[1].get<std::string>();
        const std::string extranonce2 = p[2].get<std::string>();
        const std::string ntime_hex   = p[3].get<std::string>();
        const std::string nonce_hex   = p[4].get<std::string>();

        std::cout << "[SUBMIT] worker=" << worker
                  << " job_id=" << job_id
                  << " ntime=" << ntime_hex
                  << " nonce=" << nonce_hex
                  << " algo=" << (int)current_algo
                  << "\n";

        const uint32_t ntime = (uint32_t)strtoul(ntime_hex.c_str(), nullptr, 16);
        const uint32_t nonce = (uint32_t)strtoul(nonce_hex.c_str(), nullptr, 16);

        if (job_mintime && ntime <= job_mintime) {
            std::cout << "[LOCAL REJECT] ntime too old: ntime=" << ntime
                      << " mintime=" << job_mintime << "\n";

            json resp{{"id", id}, {"error", nullptr}, {"result", false}};
            send_json(resp);

            // Force a new clean job
            send_job_notify(true);
            return;
        }

        // Build coinbase + merkle
        const std::string full_coinbase_hex = job_coinb1 + extranonce1 + extranonce2 + job_coinb2;

        std::vector<std::string> txs_for_merkle;
        txs_for_merkle.reserve(1 + job_txs_no_coinbase_hex.size());
        txs_for_merkle.push_back(full_coinbase_hex);
        txs_for_merkle.insert(txs_for_merkle.end(),
                              job_txs_no_coinbase_hex.begin(),
                              job_txs_no_coinbase_hex.end());

        const uint256 merkle_root = ComputeMerkleRootFromTxs(txs_for_merkle);

        // Compute header80 + pow hash
        const auto header80 = build_classic_header80(ntime, nonce, merkle_root.ToString());
        const uint256 pow_hash = ComputePowHashForHeader(header80, current_algo);

        uint256 target;
        target.SetHex(job_target_daemon);

        const bool accepted = UintToArith256(pow_hash) <= UintToArith256(target);

        std::cout << "  pow_hash=" << pow_hash.ToString() << "\n";
        std::cout << "  target  =" << target.ToString() << "\n";
        std::cout << "  accepted=" << (accepted ? "YES" : "NO") << "\n";

        if (accepted) {
            std::cout << ">>> BLOCK CANDIDATE FOUND (height=" << job_height << ")\n";
            submit_block_candidate_classic(header80, full_coinbase_hex);

            try {
                send_job_notify(true);
                std::cout << "[INFO] New job sent after block candidate\n";
            } catch (const std::exception& e) {
                std::cerr << "[WARN] Failed to send job after block: " << e.what() << "\n";
            }
        }

        json resp{{"id", id}, {"error", nullptr}, {"result", accepted}};
        send_json(resp);
    }

    // -------------------------------------------------------------------------
    // Main loop
    // -------------------------------------------------------------------------
    void run() {
        try {
            while (running) {
                auto lineOpt = read_line();
                if (!lineOpt) {
                    std::cout << "[INFO] Client disconnected\n";
                    break;
                }
                const std::string& line = *lineOpt;
                if (line.empty()) continue;

                std::cout << "[CLIENT ->] " << line << "\n";

                json req;
                try {
                    req = json::parse(line);
                } catch (const std::exception& e) {
                    std::cerr << "[WARN] invalid JSON: " << e.what() << "\n";
                    continue;
                }

                const std::string method = req.value("method", "");
                if (method.empty()) continue;

                if (method == "mining.subscribe") {
                    const int id = req.value("id", 0);

                    std::string agent;
                    if (req.contains("params") && req["params"].is_array() &&
                        !req["params"].empty() && req["params"][0].is_string()) {
                        agent = req["params"][0].get<std::string>();
                    }

                    const std::string agent_lower = ToLower(agent);
                    const bool want_kawpow_proto =
                        (agent_lower.find("kawpowminer") != std::string::npos) ||
                        (agent_lower.find("kawpow") != std::string::npos) ||
                        (agent_lower.find("rvn") != std::string::npos);

                    is_kawpow_stratum = want_kawpow_proto;

                    std::cout << "[INFO] mining.subscribe agent=\"" << agent
                              << "\" -> is_kawpow_stratum=" << (is_kawpow_stratum ? "true" : "false")
                              << "\n";

                    if (is_kawpow_stratum) {
                        current_algo = AlgoType::KAWPOW;
                        send_subscribe_response_kawpow(id);
                    } else {
                        send_subscribe_response(id);
                    }

                    // Always push an initial clean job
                    send_job_notify(true);
                    continue;
                }

                if (method == "mining.authorize") {
                    const int id = req.value("id", 0);

                    std::string user, pass;
                    if (req.contains("params") && req["params"].is_array()) {
                        const auto& p = req["params"];
                        if (p.size() >= 1 && p[0].is_string()) user = p[0].get<std::string>();
                        if (p.size() >= 2 && p[1].is_string()) pass = p[1].get<std::string>();
                    }

                    std::cout << "[AUTH] user=" << user
                              << " pass=\"" << pass << "\""
                              << " current_algo=" << (int)current_algo
                              << " is_kawpow_stratum=" << (is_kawpow_stratum ? "true" : "false")
                              << "\n";

                    bool need_clean_job = false;

                    // If KAWPOW protocol detected at subscribe, do not override via password.
                    if (is_kawpow_stratum) {
                        current_algo = AlgoType::KAWPOW;
                    } else {
                        if (!pass.empty()) {
                            auto algoOpt = ExtractAlgoFromMinerPassword(pass);
                            if (algoOpt.has_value()) {
                                AlgoType wanted = ParseAlgo(*algoOpt);
                                if (wanted != current_algo) {
                                    std::cout << "[AUTH] algo override -> " << *algoOpt
                                              << " (enum=" << (int)wanted << ")\n";
                                    current_algo = wanted;
                                    need_clean_job = true;
                                }
                            }
                        }
                    }

                    send_authorize_response(id, true);

                    // If algo changed, push a clean job
                    if (need_clean_job) send_job_notify(true);
                    continue;
                }

                if (method == "mining.submit") {
                    handle_submit(req);
                    continue;
                }

                if (method == "mining.extranonce.subscribe") {
                    json resp{{"id", req.value("id", 0)}, {"error", nullptr}, {"result", true}};
                    send_json(resp);
                    continue;
                }

                std::cout << "[INFO] unknown stratum method=\"" << method << "\" full=" << req.dump() << "\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERR] StratumSession exception: " << e.what() << "\n";
        }
    }
};

// -----------------------------------------------------------------------------
// Server accept loop
// -----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <listen_port> <rpc_url> <rpc_user> <rpc_pass>\n";
        std::cerr << "Example: " << argv[0]
                  << " 3333 http://127.0.0.1:8332 megabytesrpc pass\n";
        return 1;
    }

    const int port = std::stoi(argv[1]);
    const std::string rpc_url  = argv[2];
    const std::string rpc_user = argv[3];
    const std::string rpc_pass = argv[4];

    curl_global_init(CURL_GLOBAL_ALL);
    RpcClient rpc(rpc_url, rpc_user + ":" + rpc_pass);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 16) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    std::cout << "[*] Stratum listening on port " << port
              << " (KAWPOW_DIFF_FACTOR=" << KAWPOW_DIFF_FACTOR << ")\n";

    while (true) {
        sockaddr_in cli_addr{};
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(listen_fd, (sockaddr*)&cli_addr, &cli_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        std::cout << "[*] New Stratum client connected\n";

        std::thread([client_fd, &rpc]() {
            StratumSession sess(client_fd, rpc);
            sess.run();
        }).detach();
    }

    close(listen_fd);
    curl_global_cleanup();
    return 0;
}
