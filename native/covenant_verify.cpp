// LOCAL PROPOSAL MODEL. Linked-prevout Script checks only, not a Bitcoin network node.
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <streams.h>
#include <util/strencodings.h>
#include <hash.h>
#include <chrono>
#include <optional>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static CTransaction Read(const char* path) {
    std::ifstream in(path);
    std::string hex, extra;
    if (!(in >> hex) || (in >> extra) || !IsHex(hex)) throw std::runtime_error("invalid hex file");
    DataStream stream(ParseHex(hex));
    CTransaction tx(deserialize, TX_WITH_WITNESS, stream);
    if (!stream.empty()) throw std::runtime_error("trailing transaction bytes");
    return tx;
}

// Compute BIP446 independently of Core's witness-v1 precomputation detection.
class DemoChecker : public TransactionSignatureChecker {
    const CTransaction& tx;
    const uint32_t index;
public:
    mutable std::optional<uint256> last_template_hash;
    DemoChecker(const CTransaction& t, uint32_t i, CAmount amount, const PrecomputedTransactionData& data)
        : TransactionSignatureChecker(&t, i, amount, data, MissingDataBehavior::FAIL), tx(t), index(i) {}
    bool DemoTemplateHash(uint256& out, const ScriptExecutionData& execdata) const override {
        if (!execdata.m_annex_init) return false;
        HashWriter sequences, outputs;
        for (const auto& input : tx.vin) sequences << input.nSequence;
        for (const auto& output : tx.vout) outputs << output;
        auto h = TaggedHash("TemplateHash");
        h << tx.version << tx.nLockTime << sequences.GetSHA256() << outputs.GetSHA256()
          << uint8_t(execdata.m_annex_present) << index;
        if (execdata.m_annex_present) h << execdata.m_annex_hash;
        out = h.GetSHA256();
        last_template_hash = out;
        return true;
    }
};

int main(int argc, char** argv) {
    try {
        if (argc < 3) throw std::runtime_error("usage: btc-pq-covenant-verify spend.hex parent0.hex [parent1.hex ...]");
        const CTransaction tx = Read(argv[1]);
        if (argc != static_cast<int>(tx.vin.size()) + 2) throw std::runtime_error("one linked parent per input required");
        std::vector<CTxOut> prevouts;
        CAmount total = 0;
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const CTransaction parent = Read(argv[i+2]);
            const auto& outpoint = tx.vin[i].prevout;
            if (parent.GetHash() != outpoint.hash || outpoint.n >= parent.vout.size())
                throw std::runtime_error("funding transaction does not match input outpoint");
            prevouts.push_back(parent.vout[outpoint.n]);
            total += prevouts.back().nValue;
        }
        PrecomputedTransactionData data;
        data.Init(tx, std::vector<CTxOut>(prevouts), true);
        // Modern GetBlockScriptFlags plus the explicit local proposal flag.
        script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
            SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY};
        flags |= SCRIPT_VERIFY_BTC_PQ_COVENANT_DEMO;
        bool all = true;
        std::cout << "{\"core_version\":\"31.1\",\"scope\":\"linked_prevout_script_verification\","
                  << "\"consensus_modified\":true,\"proposal_model\":\"BIP347+BIP360v0.12.1+BIP446\","
                  << "\"flags\":" << flags.as_int() << ",\"inputs\":[";
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;
            DemoChecker checker(tx, i, prevouts[i].nValue, data);
            const auto start = std::chrono::steady_clock::now();
            bool ok = VerifyScript(tx.vin[i].scriptSig, prevouts[i].scriptPubKey, &tx.vin[i].scriptWitness, flags, checker, &error);
            const auto elapsed = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
            if (i) std::cout << ',';
            std::cout << "{\"index\":" << i << ",\"valid\":" << (ok ? "true" : "false") << ",\"error\":\"" << ScriptErrorString(error) << "\",\"script_microseconds\":" << elapsed
                      << ",\"template_hash\":";
            if (checker.last_template_hash) std::cout << '\"' << HexStr(*checker.last_template_hash) << '\"';
            else std::cout << "null";
            std::cout << '}';
            all &= ok;
        }
        for (const auto& out : tx.vout) total -= out.nValue;
        std::cout << "],\"fee_sats\":" << total << ",\"valid\":" << (all ? "true" : "false") << "}\n";
        return all ? 0 : 1;
    } catch (const std::exception&) {
        std::cerr << "Invalid input: require a parseable spend and its exact parent transaction for each input.\n";
        return 2;
    }
}
