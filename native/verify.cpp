// Research wrapper around unmodified Bitcoin Core 31.1 consensus Script code.
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <streams.h>
#include <util/strencodings.h>
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

int main(int argc, char** argv) {
    try {
        if (argc < 3) throw std::runtime_error("usage: btc-pq-verify spend.hex parent0.hex [parent1.hex ...]");
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
        // Exactly modern GetBlockScriptFlags, no policy-only flags, no fallback.
        script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
            SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY};
#ifdef BTC_PQ_TOY_EXPERIMENT
        // Only the separate experimental binary enables this consensus change.
        flags |= SCRIPT_VERIFY_BTC_PQ_TOY;
#endif
        bool all = true;
        std::cout << "{\"core_version\":\"31.1\",\"scope\":\"linked_prevout_script_verification\","
#ifdef BTC_PQ_TOY_EXPERIMENT
                  << "\"consensus_modified\":true,\"qsb_exact_reproduction\":false,"
#endif
                  << "\"flags\":" << flags.as_int() << ",\"inputs\":[";
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;
            TransactionSignatureChecker checker(&tx, i, prevouts[i].nValue, data, MissingDataBehavior::FAIL);
            bool ok = VerifyScript(tx.vin[i].scriptSig, prevouts[i].scriptPubKey, &tx.vin[i].scriptWitness, flags, checker, &error);
            if (i) std::cout << ',';
            std::cout << "{\"index\":" << i << ",\"valid\":" << (ok ? "true" : "false") << ",\"error\":\"" << ScriptErrorString(error) << "\"}";
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
