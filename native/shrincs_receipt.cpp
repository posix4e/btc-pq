// Shared transaction-level proof rules for the CLI and patched regtest node.
#include "shrincs_receipt.h"
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>

extern "C" int btc_pq_receipt_verify(const unsigned char*, size_t, const unsigned char*, const unsigned char*);
using Bytes = std::vector<unsigned char>;
const Bytes MAGIC{'B','T','C','-','P','Q','-','P','R','O','O','F',1};
// Protocol version 1 authorizes this exact, saved SHRINCS verifier program.
const Bytes IMAGE = ParseHex("025c847d7ffd433115e47c59802a40d334db1ec89a272235f4756faebb94b694");

static void Require(bool condition, const char* error) { if (!condition) throw std::runtime_error(error); }
class GroupChecker : public TransactionSignatureChecker {
    const CTransaction& tx;
    const uint32_t index;
    const PrecomputedTransactionData& data;
public:
    mutable unsigned requests{0};
    mutable Bytes key;
    mutable std::optional<uint256> message;
    GroupChecker(const CTransaction& t, uint32_t i, CAmount value, const PrecomputedTransactionData& d)
        : TransactionSignatureChecker(&t, i, value, d, MissingDataBehavior::FAIL), tx(t), index(i), data(d) {}
    bool DemoCheckShrincs(std::span<const unsigned char> sig, std::span<const unsigned char> pk, ScriptExecutionData& execdata) const override {
        if (!sig.empty() || pk.size() != 32 || requests++) return false;
        uint256 sighash;
        if (!SignatureHashSchnorr(sighash, execdata, tx, index, SIGHASH_DEFAULT,
                                 SigVersion::TAPSCRIPT, data, MissingDataBehavior::FAIL)) return false;
        key.assign(pk.begin(), pk.end());
        message = (TaggedHash("btc-pq/SHRINCS-B32/v1") << sighash).GetSHA256();
        // This collects the claim. Overall transaction acceptance also requires
        // the shared receipt below; no input is authorized by this return alone.
        return true;
    }
};

script_verify_flags ShrincsReceiptFlags(script_verify_flags flags) {
    return flags | SCRIPT_VERIFY_BTC_PQ_COVENANT_DEMO | SCRIPT_VERIFY_BTC_PQ_SHRINCS_DEMO | SCRIPT_VERIFY_BTC_PQ_SHRINCS_PROOF_DEMO;
}

bool HasShrincsReceiptEnvelope(const CTransaction& tx) {
    // Include unknown versions so they are rejected by the common decoder.
    for (const auto& input : tx.vin) {
        const auto& stack = input.scriptWitness.stack;
        if (!stack.empty() && stack[0].size() >= MAGIC.size()-1 &&
            std::equal(MAGIC.begin(), MAGIC.end()-1, stack[0].begin())) return true;
    }
    return false;
}

UniValue CheckShrincsReceiptTransaction(const CTransaction& encoded,
        const std::vector<CTxOut>& prevouts, script_verify_flags flags) {
    UniValue result(UniValue::VOBJ);
    try {
        Require(!encoded.IsCoinBase() && !encoded.vin.empty() && encoded.vin.size() <= 512, "input count");
        Require(prevouts.size() == encoded.vin.size(), "one prevout per input required");
        TxValidationState state;
        Require(CheckTransaction(encoded, state), "context-independent transaction checks");
        const int64_t weight = GetTransactionWeight(encoded);
        Require(weight <= MAX_BLOCK_WEIGHT, "transaction cannot fit within block weight");
        result.pushKV("transaction_bytes", GetSerializeSize(TX_WITH_WITNESS(encoded)));
        result.pushKV("weight", weight);
        result.pushKV("vbytes", (weight+3)/4);

        CMutableTransaction stripped(encoded);
        const auto& carrier = encoded.vin[0].scriptWitness.stack;
        Require(carrier.size() == 4, "first input must carry exactly one proof envelope");
        const auto& envelope = carrier[0];
        Require(envelope.size() > MAGIC.size() && std::equal(MAGIC.begin(),MAGIC.end(),envelope.begin()), "proof envelope version");
        const Bytes proof(envelope.begin()+MAGIC.size(), envelope.end());
        stripped.vin[0].scriptWitness.stack.erase(stripped.vin[0].scriptWitness.stack.begin());
        for (const auto& input : stripped.vin) {
            const auto& w = input.scriptWitness.stack;
            Require(w.size() == 3 && w[0].empty(), "all inputs must request the same aggregate group");
            Require(w[1].size() == 34 && w[1][0] == 0x20 && w[1][33] == 0xcf, "one exact SHRINCS leaf per input");
            Require(w[2].size() == 33, "one-level P2MR control path required");
        }
        const CTransaction tx(stripped);
        CAmount fee = 0;
        for (const auto& prevout : prevouts) {
            const auto& spk = prevout.scriptPubKey;
            Require(spk.size() == 34 && spk[0] == OP_2 && spk[1] == 0x20, "all group inputs must spend P2MR");
            Require(MoneyRange(prevout.nValue), "spent amount range");
            fee += prevout.nValue;
            Require(MoneyRange(fee), "total spent amount range");
        }
        for (const auto& output : tx.vout) fee -= output.nValue;
        Require(fee >= 0, "outputs exceed inputs");

        PrecomputedTransactionData data;
        data.Init(tx, std::vector<CTxOut>(prevouts), true);
        Require((flags & SCRIPT_VERIFY_BTC_PQ_SHRINCS_PROOF_DEMO) != 0, "receipt rule not enabled");
        CSHA256 claim;
        const std::string domain = "btc-pq/SHRINCS-proof-claims/v1";
        claim.Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size());
        const unsigned char zero = 0;
        claim.Write(&zero, 1);
        const uint32_t count = tx.vin.size();
        const unsigned char encoded_count[4]{static_cast<unsigned char>(count),static_cast<unsigned char>(count>>8),static_cast<unsigned char>(count>>16),static_cast<unsigned char>(count>>24)};
        claim.Write(encoded_count, 4);
        bool scripts_valid = true;
        UniValue inputs(UniValue::VARR);
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            GroupChecker checker(tx, i, prevouts[i].nValue, data);
            ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;
            const bool valid = VerifyScript(tx.vin[i].scriptSig, prevouts[i].scriptPubKey, &tx.vin[i].scriptWitness, flags, checker, &error)
                               && checker.requests == 1 && checker.message.has_value();
            UniValue row(UniValue::VOBJ);
            row.pushKV("index", uint64_t(i)); row.pushKV("script_valid", valid); row.pushKV("error", ScriptErrorString(error));
            if (valid) {
                claim.Write(checker.key.data(), 32).Write(checker.message->begin(), 32);
                row.pushKV("message_digest", HexStr(*checker.message));
            }
            scripts_valid &= valid; inputs.push_back(row);
        }
        result.pushKV("inputs", inputs);
        unsigned char journal[32]; claim.Finalize(journal);
        result.pushKV("claims_digest", HexStr(journal));
        result.pushKV("image_id", HexStr(IMAGE));
        const auto start = std::chrono::steady_clock::now();
        const bool authorized = scripts_valid && btc_pq_receipt_verify(proof.data(), proof.size(), IMAGE.data(), journal) == 1;
        const double ms = std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
        result.pushKV("proof_bytes", uint64_t(proof.size())); result.pushKV("proof_verify_ms", ms);
        result.pushKV("fee_sats", fee); result.pushKV("group_authorized", authorized); result.pushKV("valid", authorized);
    } catch (const std::exception& error) {
        result.pushKV("valid", false); result.pushKV("error", error.what());
    }
    return result;
}
