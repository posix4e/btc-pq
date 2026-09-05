// Bounded CPU search for the exact published hash-to-DER predicate.
// Public data only: a fixed DER signature (r,s), a transaction sighash template,
// libsecp256k1 public-key recovery, SHA-256, and Bitcoin Core's strict DER
// syntax rules. No validation rule is changed; Core decides validity.
#include <crypto/sha256.h>
#include <secp256k1.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using Bytes = std::vector<unsigned char>;
using Hash = std::array<unsigned char,32>;
using Clock = std::chrono::steady_clock;
static double Seconds(Clock::time_point t) { return std::chrono::duration<double>(Clock::now()-t).count(); }
static Bytes Hex(const UniValue& v) { const auto s=v.get_str(); if (!s.empty() && !IsHex(s)) throw std::runtime_error("invalid hex"); return ParseHex(s); }
static void Add(Bytes& a,const Bytes& b) { a.insert(a.end(),b.begin(),b.end()); }
static void LE(Bytes& a,uint64_t n,unsigned size) { for(unsigned j=0;j<size;++j) a.push_back((n>>(8*j))&255); }
static void Compact(Bytes& a,size_t n) {
    if(n<253) a.push_back(n); else if(n<=65535) { a.push_back(253); LE(a,n,2); }
    else { a.push_back(254); LE(a,n,4); }
}
static Hash Finish(CSHA256 state,const Bytes& tail) {
    Hash h; state.Write(tail.data(),tail.size()).Finalize(h.data());
    CSHA256().Write(h.data(),h.size()).Finalize(h.data()); return h;
}
static CSHA256 PrefixState(const Bytes& prefix,const Bytes& code) {
    Bytes before=prefix; Compact(before,code.size()); Add(before,code);
    return CSHA256().Write(before.data(),before.size());
}

// Exact port of Bitcoin Core IsValidSignatureEncoding (script/interpreter.cpp).
static bool StrictDER(const unsigned char* sig,size_t size) {
    if(size<9 || size>73) return false;
    if(sig[0]!=0x30 || sig[1]!=size-3) return false;
    unsigned lenR=sig[3]; if(5+lenR>=size) return false;
    unsigned lenS=sig[5+lenR]; if(lenR+lenS+7!=size) return false;
    if(sig[2]!=0x02 || lenR==0 || (sig[4]&0x80)) return false;
    if(lenR>1 && sig[4]==0x00 && !(sig[5]&0x80)) return false;
    if(sig[lenR+4]!=0x02 || lenS==0 || (sig[lenR+6]&0x80)) return false;
    if(lenS>1 && sig[lenR+6]==0x00 && !(sig[lenR+7]&0x80)) return false;
    return true;
}

// Q_p = (s/r)*R_p + (-z/r)*G for both parities p of the fixed signature's R.
struct Recovery {
    secp256k1_context* ctx{secp256k1_context_create(SECP256K1_CONTEXT_NONE)};
    secp256k1_pubkey C[2]; bool have[2]{false,false};
    Bytes neg_r_inverse;
    Recovery(const Bytes& r,const Bytes& s_over_r,const Bytes& neg_r_inv):neg_r_inverse(neg_r_inv) {
        if(r.size()!=32 || s_over_r.size()!=32 || neg_r_inv.size()!=32) throw std::runtime_error("scalar sizes");
        for(int p=0;p<2;++p) {
            Bytes compressed{static_cast<unsigned char>(2+p)}; Add(compressed,r);
            secp256k1_pubkey R;
            if(!secp256k1_ec_pubkey_parse(ctx,&R,compressed.data(),33)) continue;
            if(!secp256k1_ec_pubkey_tweak_mul(ctx,&R,s_over_r.data())) continue;
            C[p]=R; have[p]=true;
        }
        if(!have[0] && !have[1]) throw std::runtime_error("r is not a curve x-coordinate");
    }
    Recovery(const Recovery& o):neg_r_inverse(o.neg_r_inverse) { for(int p=0;p<2;++p){C[p]=o.C[p];have[p]=o.have[p];} }
    ~Recovery() { secp256k1_context_destroy(ctx); }
    // Returns number of keys written (0..2); keys[p] is the compressed key for parity p.
    int Keys(const Hash& z,std::array<Bytes,2>& keys) {
        Hash d=z;
        if(!secp256k1_ec_seckey_tweak_mul(ctx,d.data(),neg_r_inverse.data())) return 0; // z==0 or z>=n
        secp256k1_pubkey P; if(!secp256k1_ec_pubkey_create(ctx,&P,d.data())) return 0;
        int n=0;
        for(int p=0;p<2;++p) {
            keys[p].clear(); if(!have[p]) continue;
            const secp256k1_pubkey* parts[2]={&C[p],&P}; secp256k1_pubkey Q;
            if(!secp256k1_ec_pubkey_combine(ctx,&Q,parts,2)) continue;
            keys[p].resize(33); size_t len=33;
            secp256k1_ec_pubkey_serialize(ctx,keys[p].data(),&len,&Q,SECP256K1_EC_COMPRESSED); ++n;
        }
        return n;
    }
};

static Hash Sha(const Bytes& b) { Hash h; CSHA256().Write(b.data(),b.size()).Finalize(h.data()); return h; }

static UniValue Rate(uint64_t count,double seconds,const std::string& unit) {
    UniValue v(UniValue::VOBJ); v.pushKV("candidates",count); v.pushKV("wall_seconds",seconds);
    v.pushKV("candidate_unit",unit); v.pushKV("candidates_per_second",seconds>0?double(count)/seconds:0.0);
    return v;
}

static Bytes Removed(const Bytes& code,const std::vector<std::pair<size_t,size_t>>& spans,const std::vector<unsigned>& selected) {
    std::vector<std::pair<size_t,size_t>> sorted;
    for(auto i:selected) { if(i>=spans.size()) throw std::runtime_error("subset index"); sorted.push_back(spans[i]); }
    std::sort(sorted.begin(),sorted.end());
    Bytes out; out.reserve(code.size()); size_t last=0;
    for(auto [a,b]:sorted) { if(a<last || b<a || b>code.size()) throw std::runtime_error("invalid deletion spans"); out.insert(out.end(),code.begin()+last,code.begin()+a); last=b; }
    out.insert(out.end(),code.begin()+last,code.end()); return out;
}

struct HitRecord { bool found=false; uint64_t counter=0; uint32_t sequence=0; int parity=0; Hash z{}; Bytes key; Hash sig{}; std::vector<unsigned> subset; };

int main() {
    try {
        std::string text((std::istreambuf_iterator<char>(std::cin)),{});
        UniValue req; if(!req.read(text)) throw std::runtime_error("invalid JSON request");
        const std::string mode=req["mode"].get_str();
        Recovery base(Hex(req["r_hex"]),Hex(req["s_over_r_hex"]),Hex(req["neg_r_inverse_hex"]));
        UniValue out(UniValue::VOBJ);
        out.pushKV("consensus_changes",UniValue(UniValue::VARR));
        out.pushKV("search_method","libsecp256k1: one fixed-base multiplication per sighash, both recovery parities; SHA-256 of the compressed key; Core strict-DER syntax");
        if(mode=="vectors") {
            UniValue rows(UniValue::VARR);
            for(const auto& value:req["digests"].getValues()) {
                const auto raw=Hex(value); if(raw.size()!=32) throw std::runtime_error("digest size");
                Hash z; std::copy(raw.begin(),raw.end(),z.begin());
                std::array<Bytes,2> keys; base.Keys(z,keys);
                UniValue row(UniValue::VOBJ); row.pushKV("digest_hex",HexStr(z));
                UniValue ks(UniValue::VARR), passes(UniValue::VARR), sigs(UniValue::VARR);
                for(int p=0;p<2;++p) { ks.push_back(HexStr(keys[p])); Hash s=Sha(keys[p]); sigs.push_back(keys[p].empty()?"":HexStr(s)); passes.push_back(!keys[p].empty() && StrictDER(s.data(),32)); }
                row.pushKV("keys_hex",ks); row.pushKV("puzzle_signatures_hex",sigs); row.pushKV("strict_der",passes); rows.push_back(row);
            }
            out.pushKV("vectors",rows); std::cout<<out.write()<<'\n'; return 0;
        }
        const uint64_t maximum=req["max_candidates"].getInt<uint64_t>();
        const double max_seconds=req["max_seconds"].get_real();
        unsigned threads=req.exists("threads")?req["threads"].getInt<unsigned>():1;
        if(!maximum || !(max_seconds>0) || !threads || threads>256) throw std::runtime_error("invalid search budget");
        if(mode!="pin" && mode!="subset") throw std::runtime_error("unknown search mode");
        Bytes prefix=Hex(req["prefix_hex"]),tail=Hex(req["tail_hex"]),code=Hex(req["code_hex"]);
        const uint64_t first=req.exists("counter")?req["counter"].getInt<uint64_t>():0;
        std::vector<std::pair<size_t,size_t>> spans; unsigned t=0; uint32_t fixed_sequence=0;
        if(mode=="subset") {
            for(const auto& span:req["spans"].getValues()) spans.emplace_back(span[0].getInt<size_t>(),span[1].getInt<size_t>());
            t=req["selections"].getInt<unsigned>(); fixed_sequence=req["sequence"].getInt<uint32_t>();
            if(spans.size()>1024 || !t || t>spans.size()) throw std::runtime_error("invalid table dimensions");
        }
        const CSHA256 pin_state=PrefixState(prefix,code);
        std::atomic<bool> stop{false}; std::atomic<uint64_t> total{0}, invalid{0}; std::mutex lock; HitRecord hit;
        std::vector<uint64_t> per_thread(threads,0); bool space_exhausted=false;
        auto