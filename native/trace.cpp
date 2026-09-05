// Observe the stock signature checker's inputs and outputs without changing Core.
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <fstream>
#include <iostream>
#include <stdexcept>

static CTransaction Read(const char* path) {
    std::ifstream in(path);
    std::string hex, extra;
    if (!(in >> hex) || (in >> extra) || !IsHex(hex)) throw std::runtime_error("invalid transaction hex");
    DataStream stream(ParseHex(hex));
    CTransaction tx(deserialize, TX_WITH_WITNESS, stream);
    if (!stream.empty()) throw std::runtime_error("trailing transaction bytes");
    return tx;
}

class TraceChecker : public TransactionSignatureChecker {
    const CTransaction& tx;
    unsigned index;
    CAmount amount;
    const PrecomputedTransactionData& data;
    UniValue& checks;
public:
    TraceChecker(const CTransaction& t, unsigned i, CAmount a,
                 const PrecomputedTransactionData& d, UniValue& rows)
        : TransactionSignatureChecker(&t, i, a, d, MissingDataBehavior::FAIL),
          tx(t), index(i), amount(a), data(d), checks(rows) {}

    bool CheckECDSASignature(const std::vector<unsigned char>& sig,
                            const std::vector<unsigned char>& key,
                            const CScript& code, SigVersion version) const override {
        const bool valid = TransactionSignatureChecker::CheckECDSASignature(sig, key, code, version);
        UniValue row(UniValue::VOBJ);
        row.pushKV("input_index", uint64_t(index));
        row.pushKV("signature_hex", HexStr(sig));
        row.pushKV("public_key_hex", HexStr(key));
        row.pushKV("script_code_hex", HexStr(code));
        row.pushKV("sigversion", version == SigVersion::BASE ? "BASE" : "WITNESS_V0");
        if (!sig.empty()) {
            const auto z = SignatureHash(code, tx, index, int32_t(sig.back()), amount, version, &data);
            row.pushKV("sighash_byte", uint64_t(sig.back()));
            // Raw digest bytes as passed to ECDSA, not uint256 display order.
            row.pushKV("digest_hex", HexStr(z));
        }
        row.pushKV("valid", valid);
        checks.push_back(row);
        return valid;
    }
};

int main(int argc, char** argv) {
    try {
        if (argc < 3) throw std::runtime_error("usage: btc-pq-trace spend.hex parent0.hex [parent1.hex ...]");
        const CTransaction tx = Read(argv[1]);
        if (argc != int(tx.vin.size()) + 2) throw std::runtime_error("one linked parent per input required");
        std::vector<CTxOut> prevouts;
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const auto parent = Read(argv[i + 2]);
            const auto& ref = tx.vin[i].prevout;
            if (parent.GetHash() != ref.hash || ref.n >= parent.vout.size())
                throw std::runtime_error("parent/outpoint mismatch");
            prevouts.push_back(parent.vout[ref.n]);
        }
        PrecomputedTransactionData data;
        data.Init(tx, std::vector<CTxOut>(prevouts), true);
        const script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
            SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY};
        UniValue out(UniValue::VOBJ), checks(UniValue::VARR), inputs(UniValue::VARR);
        bool all = true;
        for (unsigned i = 0; i < tx.vin.size(); ++i) {
            TraceChecker checker(tx, i, prevouts[i].nValue, data, checks);
            ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;
            const bool valid = VerifyScript(tx.vin[i].scriptSig, prevouts[i].scriptPubKey,
                                           &tx.vin[i].scriptWitness, flags, checker, &error);
            UniValue row(UniValue::VOBJ);
            row.pushKV("index", uint64_t(i)); row.pushKV("valid", valid);
            row.pushKV("error", ScriptErrorString(error)); inputs.push_back(row);
            all &= valid;
        }
        out.pushKV("core_version", "31.1"); out.pushKV("consensus_modified", false);
        out.pushKV("flags", uint64_t(flags.as_int())); out.pushKV("valid", all);
        out.pushKV("inputs", inputs); out.pushKV("checks", checks);
        std::cout << out.write() << '\n';
        return all ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "trace: " << error.what() << '\n'; return 2;
    }
}
