#ifndef BTC_PQ_SHRINCS_RECEIPT_H
#define BTC_PQ_SHRINCS_RECEIPT_H

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <univalue.h>

script_verify_flags ShrincsReceiptFlags(script_verify_flags flags);
bool HasShrincsReceiptEnvelope(const CTransaction& tx);
// Prevouts must come from the caller's authoritative UTXO view, in input order.
// Returns valid=true only after every script and the common receipt verify.
UniValue CheckShrincsReceiptTransaction(const CTransaction& tx,
    const std::vector<CTxOut>& prevouts, script_verify_flags flags);

#endif
