// Research fixture operations and the persistent signer's reserved-counter backend.
#include "shrincs_bridge.h"
#include <shrincs.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<unsigned char>;

static double Millis(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now()-start).count();
}
static Bytes ReadHex(const fs::path& path) {
    std::ifstream in(path);
    std::string hex, extra;
    if (!(in >> hex) || (in >> extra) || hex.size()%2) throw std::runtime_error("invalid hex input");
    Bytes result;
    auto digit = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return c-'0';
        if (c >= 'a' && c <= 'f') return c-'a'+10;
        if (c >= 'A' && c <= 'F') return c-'A'+10;
        throw std::runtime_error("invalid hex character");
    };
    for (size_t i = 0; i < hex.size(); i += 2) result.push_back(digit(hex[i])*16+digit(hex[i+1]));
    return result;
}
static std::string Hex(std::span<const unsigned char> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string s;
    for (auto c : bytes) { s += digits[c>>4]; s += digits[c&15]; }
    return s;
}
static void Write(const fs::path& path, const std::string& value) {
    std::ofstream out(path);
    if (!(out << value << '\n')) throw std::runtime_error("cannot write fixture");
}
static Bytes Encode(const SHRINCS::PublicKey& pk) {
    Bytes bytes = pk.seed;
    bytes.insert(bytes.end(), pk.root.begin(), pk.root.end());
    return bytes;
}

int main(int argc, char** argv) {
    try {
        if (argc < 2) throw std::runtime_error("expected pubkey, fixture, or verify");
        const std::string command = argv[1];
        if (command == "verify" && argc == 5) {
            const auto pk = ReadHex(argv[2]), message = ReadHex(argv[3]), sig = ReadHex(argv[4]);
            const auto start = Clock::now();
            const bool valid = DemoShrincsVerify(message, sig, pk);
            std::cout << "{\"valid\":" << (valid ? "true" : "false") << ",\"verify_ms\":" << Millis(start) << "}\n";
            return valid ? 0 : 1;
        }
        if (!((command == "pubkey" && argc == 3) || (command == "fixture" && argc == 5) ||
              (command == "sign-reserved" && argc == 5)))
            throw std::runtime_error("usage: pubkey seed.hex | fixture seed.hex message.hex directory | verify pk.hex message.hex sig.hex | sign-reserved seed.hex message.hex q-or-recovery");
        const auto seed = ReadHex(argv[2]);
        if (seed.size() != 3*Parameters::N) throw std::runtime_error("48-byte public test seed required");
        SHRINCS::PublicKey pk;
        SHRINCS::SecretKey sk;
        SHRINCS::State state;
        const auto start = Clock::now();
        SHRINCS::shrincs_restore(seed.data(), pk, sk, state);
        const auto derive_ms = Millis(start);
        const Bytes encoded = Encode(pk);
        if (command == "pubkey") {
            std::cout << "{\"public_key\":\"" << Hex(encoded) << "\",\"derive_ms\":" << derive_ms
                      << ",\"restored_state_valid\":" << (state.valid ? "true" : "false") << "}\n";
            return 0;
        }
        const auto message = ReadHex(argv[3]);
        if (message.size() != 32) throw std::runtime_error("32-byte transaction digest required");
        if (command == "sign-reserved") {
            // The Python state manager has durably consumed this position first.
            // Calling this low-level research backend directly supplies no state safety.
            const std::string position(argv[4]);
            const bool recovery = position == "recovery";
            uint32_t q = 0;
            if (!recovery) {
                size_t parsed = 0;
                const auto value = std::stoul(position, &parsed);
                if (parsed != position.size() || value < 1 || value > Parameters::HSF+1)
                    throw std::runtime_error("reserved counter outside compact range");
                q = static_cast<uint32_t>(value);
                state.q = q-1;
                state.valid = true;
            }
            const auto sign_start = Clock::now();
            std::unique_ptr<unsigned char[]> signature(recovery ?
                SHRINCS::shrincs_sign_stateless(message, sk) : SHRINCS::shrincs_sign_stateful(message, sk, state));
            if (!signature || (!recovery && state.q != q)) throw std::runtime_error("reserved signing failed");
            const auto size = recovery ? Parameters::SL_SIZE :
                Parameters::N + Parameters::WOTS_SIGN_LEN + std::min(q, Parameters::HSF)*Parameters::N;
            const std::span<const unsigned char> sig(signature.get(), size);
            const double sign_ms = Millis(sign_start);
            if (!DemoShrincsVerify(message, sig, encoded)) throw std::runtime_error("reserved signature self-check failed");
            std::cout << "{\"public_key\":\"" << Hex(encoded) << "\",\"signature\":\"" << Hex(sig)
                      << "\",\"q\":" << q << ",\"mode\":\"" << (recovery ? "recovery" : "compact")
                      << "\",\"sign_ms\":" << sign_ms << ",\"derive_ms\":" << derive_ms << "}\n";
            return 0;
        }
        const fs::path directory(argv[4]);
        fs::create_directories(directory);
        Write(directory/"public-key.hex", Hex(encoded));
        std::ostringstream json;
        json << "{\"parameters\":\"SHRINCS_B32\",\"N\":16,\"HSF\":210,\"HSL\":32,\"D\":4,"
             << "\"public_fixture_only\":true,\"key_derivation_ms\":" << derive_ms
             << ",\"signer_hardware_threads\":" << std::thread::hardware_concurrency() << ",\"signatures\":[";
        // Same initialization as upstream KATs: this fixture is a fresh signer,
        // with a publicly specified seed. It is not seed-restoration behavior.
        state.valid = true;
        bool first = true;
        for (uint32_t q = 1; q <= 17; ++q) {
            const auto sign_start = Clock::now();
            std::unique_ptr<unsigned char[]> signature(SHRINCS::shrincs_sign_stateful(message, sk, state));
            const double sign_ms = Millis(sign_start);
            if (state.q != q) throw std::runtime_error("state did not advance");
            if (q != 1 && q != 2 && q != 17) continue;
            const size_t size = Parameters::N + Parameters::WOTS_SIGN_LEN + q*Parameters::N;
            const std::span<const unsigned char> sig(signature.get(), size);
            const auto verify_start = Clock::now();
            if (!DemoShrincsVerify(message, sig, encoded)) throw std::runtime_error("stateful self-check failed");
            const double verify_ms = Millis(verify_start);
            const std::string name = "compact-q"+std::to_string(q);
            Write(directory/(name+".sig.hex"), Hex(sig));
            if (!first) json << ',';
            first = false;
            json << "{\"name\":\"" << name << "\",\"q\":" << q << ",\"bytes\":" << size
                 << ",\"sign_ms\":" << sign_ms << ",\"verify_ms\":" << verify_ms << '}';
        }
        // Exercise the actual restore path; never re-enable its compact state.
        SHRINCS::PublicKey restored_pk;
        SHRINCS::SecretKey restored_sk;
        SHRINCS::State restored_state;
        const auto restore_start = Clock::now();
        SHRINCS::shrincs_restore(seed.data(), restored_pk, restored_sk, restored_state);
        const double restore_ms = Millis(restore_start);
        if (restored_state.valid || Encode(restored_pk) != encoded) throw std::runtime_error("unexpected restore state/key");
        bool compact_rejected = false;
        try {
            std::unique_ptr<unsigned char[]> impossible(SHRINCS::shrincs_sign_stateful(message, restored_sk, restored_state));
        } catch (const std::runtime_error&) { compact_rejected = true; }
        if (!compact_rejected) throw std::runtime_error("restored compact signing unexpectedly allowed");
        const auto fallback_start = Clock::now();
        std::unique_ptr<unsigned char[]> fallback(SHRINCS::shrincs_sign_stateless(message, restored_sk));
        const double fallback_ms = Millis(fallback_start);
        if (!fallback) throw std::runtime_error("fallback signer failed");
        const std::span<const unsigned char> sig(fallback.get(), Parameters::SL_SIZE);
        const auto verify_start = Clock::now();
        if (!DemoShrincsVerify(message, sig, encoded)) throw std::runtime_error("fallback self-check failed");
        const double verify_ms = Millis(verify_start);
        Write(directory/"recovery.sig.hex", Hex(sig));
        json << ",{\"name\":\"recovery\",\"bytes\":" << sig.size() << ",\"sign_ms\":" << fallback_ms
             << ",\"verify_ms\":" << verify_ms << "}],\"compact_states_consumed\":17,"
             << "\"restored_compact_rejected\":true,\"restore_ms\":" << restore_ms << '}';
        Write(directory/"signing.json", json.str());
        std::cout << json.str() << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 2;
    }
}
