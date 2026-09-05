// Linked-parent command-line adapter for the shared transaction proof rules.
#include "shrincs_receipt.h"
#include <streams.h>
#include <util/strencodings.h>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void Require(bool condition, const char* error) { if (!condition) throw std::runtime_error(error); }
static CTransaction Read(const char* path) {
    std::ifstream in(path); std::string hex, extra;
    Require(bool(in >> hex) && !(in >> extra) && IsHex(hex), "invalid transaction hex");
    DataStream stream(ParseHex(hex));
    CTransaction tx(deserialize, TX_WITH_WITNESS, stream);
    Require(stream.empty(), "trailing transaction bytes");
    return tx;
}

int main(int argc, char** argv) {
    UniValue result(UniValue::VOBJ);
    try {
        Require(argc >= 3, "expected spend and linked parents");
        const CTransaction tx = Read(argv[1]);
        Require(argc == int(tx.vin.size())+2, "one parent per input required");
        std::vector<CTxOut> prevouts;
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const CTransaction parent = Read(argv[i+2]);
            const auto& outpoint = tx.vin[i].prevout;
            Require(parent.GetHash() == outpoint.hash && outpoint.n < parent.vout.size(), "linked parent mismatch");
            prevouts.push_back(parent.vout[outpoint.n]);
        }
        script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
            SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY};
        result = CheckShrincsReceiptTransaction(tx, prevouts, ShrincsReceiptFlags(flags));
    } catch (const std::exception& error) {
        result.pushKV("valid", false); result.pushKV("error", error.what());
    }
    result.pushKV("scope", "native_linked_prevout_transaction_proof_model");
    result.pushKV("consensus_modified", true);
    result.pushKV("network_node", false);
    std::cout << result.write() << '\n';
    return result["valid"].get_bool() ? 0 : 1;
}
