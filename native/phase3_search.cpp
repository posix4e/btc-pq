// Public-data CPU search for the exact published QSB pinning predicate.
// Off-chain measurement tool only; links the UNCHANGED Core/secp256k1 build.
//
// Per candidate z (legacy SIGHASH_ALL digest with sig_nonce FindAndDelete'd):
//   u1 = -z * r^-1 mod n;  P = u1*G;  Q_b = P + C_b  (C_b = s*r^-1*R_b fixed)
//   pass if SHA256(compressed Q_b) is a strict-DER signature with r,s >= 1.
// General ecdsa_recover is cross-checked in "vectors" mode; any DER pass is
// reported for full end-to-end validation by the Python driver.
#include <crypto/sha256.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
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
    else if(n<=65535*256ULL) { a.push_back(254); LE(a,n,4); }
}
static Hash DoubleHash(const Bytes& bytes) {
    Hash h; CSHA256().Write(bytes.data(),bytes.size()).Finalize(h.data());
    CSHA256().Write(h.data(),h.size()).Finalize(h.data()); return h;
}
static Hash Finish(CSHA256 state,const Bytes& tail) {
    Hash h; state.Write(tail.data(),tail.size()).Finalize(h.data());
    CSHA256().Write(h.data(),h.size()).Finalize(h.data()); return h;
}
static CSHA256 PrefixState(const Bytes& prefix,const Bytes& code) {
    Bytes before=prefix; Compact(before,code.size()); Add(before,code);
    return CSHA256().Write(before.data(),before.size());
}

// Mirrors vendor secp256k1.py is_valid_der_sig (BIP66 structure, any sighash
// byte) and additionally rejects r=0 or s=0, which ECDSA cannot verify.
static bool StrictDerNonzero(const unsigned char* d,size_t n) {
    if(n<9 || d[0]!=0x30 || size_t(d[1])+3!=n) return false;
    size_t idx=2;
    for(unsigned k=0;k<2;++k) {
        if(idx>=n-1 || d[idx]!=0x02) return false;
        ++idx; const size_t len=d[idx]; ++idx;
        if(!len || idx+len>n-1) return false;
        if(len>1 && d[idx]==0x00 && !(d[idx+1]&0x80)) return false;
        if(d[idx]&0x80) return false;
        bool nonzero=false;
        for(size_t j=0;j<len;++j) nonzero|=d[idx+j]!=0;
        if(!nonzero) return false;
        idx+=len;
    }
    return idx==n-1;
}

struct Recovery {
    secp256k1_context* ctx{secp256k1_context_create(SECP256K1_CONTEXT_NONE)};
    Bytes order{ParseHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};
    Bytes inverse;                       // r^-1 mod n, supplied by the driver
    std::vector<secp256k1_pubkey> constants;  // C_b = s*r^-1*R_b per valid branch
    std::vector<unsigned> recovery_ids;
    Bytes r_bytes,s_bytes;
    ~Recovery() { secp256k1_context_destroy(ctx); }
    Bytes Serialize(const secp256k1_pubkey& pub) {
        Bytes key(33); size_t n=33;
        if(!secp256k1_ec_pubkey_serialize(ctx,key.data(),&n,&pub,SECP256K1_EC_COMPRESSED)) throw std::runtime_error("serialize pubkey");
        return key;
    }
    void Load(const UniValue& req) {
        inverse=Hex(req["inverse_r_hex"]); r_bytes=Hex(req["r_hex"]); s_bytes=Hex(req["s_hex"]);
        if(inverse.size()!=32||r_bytes.size()>33||s_bytes.size()>33) throw std::runtime_error("bad scalars");
        for(const auto& point:req["branch_constants"].getValues()) {
            const auto raw=Hex(point);
            secp256k1_pubkey pub;
            if(raw.size()!=33||!secp256k1_ec_pubkey_parse(ctx,&pub,raw.data(),33)) throw std::runtime_error("bad branch constant");
            constants.push_back(pub);
        }
        if(constants.empty()||constants.size()>4) throw std::runtime_error("branch count");
        for(unsigned i=0;i<constants.size();++i)
            recovery_ids.push_back(req.exists("recovery_ids")?req["recovery_ids"][i].getInt<unsigned>():i);
    }
    // u1 = -z * r^-1 mod n, via seckey tweaks; false if u1 == 0 (z = 0 mod n).
    bool Scalar(const Hash& z,Hash& u1) {
        std::copy(z.begin(),z.end(),u1.begin());
        if(!std::lexicographical_compare(u1.begin(),u1.end(),order.begin(),order.end())) {
            int borrow=0;
            for(int j=31;j>=0;--j) { int v=int(u1[j])-order[j]-borrow; u1[j]=v&255; borrow=v<0; }
        }
        if(std::all_of(u1.begin(),u1.end(),[](unsigned char c){return c==0;})) return false;
        if(!secp256k1_ec_seckey_negate(ctx,u1.data())) return false;
        return secp256k1_ec_seckey_tweak_mul(ctx,u1.data(),inverse.data());
    }
    // Recovered candidate keys for digest z, one per valid branch.
    std::vector<std::pair<unsigned,Bytes>> Keys(const Hash& z) {
        Hash u1; std::vector<std::pair<unsigned,Bytes>> out;
        if(!Scalar(z,u1)) {
            // z == 0 mod n gives Q_b = C_b, not an empty set of keys.
            for(unsigned i=0;i<constants.size();++i) out.emplace_back(recovery_ids[i],Serialize(constants[i]));
            return out;
        }
        secp256k1_pubkey p;
        if(!secp256k1_ec_pubkey_create(ctx,&p,u1.data())) return out;
        for(unsigned i=0;i<constants.size();++i) {
            const auto& c=constants[i];
            const secp256k1_pubkey* pair[2]={&p,&c}; secp256k1_pubkey q;
            if(!secp256k1_ec_pubkey_combine(ctx,&q,pair,2)) continue;  // negligible P=-C case
            out.emplace_back(recovery_ids[i],Serialize(q));
        }
        return out;
    }
    // Reference general recovery through libsecp256k1 (cross-check path).
    Bytes General(const Hash& z,int recid) {
        Bytes compact=r_bytes; compact.insert(compact.end(),s_bytes.begin(),s_bytes.end());
        compact.resize(64,0);
        secp256k1_ecdsa_recoverable_signature sig;
        if(!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&sig,compact.data(),recid)) return {};
        secp256k1_pubkey pub;
        if(!secp256k1_ecdsa_recover(ctx,&pub,&sig,z.data())) return {};
        return Serialize(pub);
    }
};

static UniValue Rate(uint64_t count,double seconds,const std::string& unit) {
    UniValue v(UniValue::VOBJ); v.pushKV("candidates",count); v.pushKV("wall_seconds",seconds);
    v.pushKV("candidate_unit",unit); v.pushKV("candidates_per_second",seconds>0?double(count)/seconds:0.0);
    return v;
}
static UniValue Event(uint64_t counter,const Hash& z,unsigned branch,const Bytes& key,const Hash& h) {
    UniValue v(UniValue::VOBJ);
    v.pushKV("winning_counter",counter); v.pushKV("digest_hex",HexStr(z));
    v.pushKV("recovery_branch",uint64_t(branch)); v.pushKV("key_nonce_hex",HexStr(key));
    v.pushKV("sha256_key_hex",HexStr(h));
    return v;
}

int main() {
    try {
        std::string text((std::istreambuf_iterator<char>(std::cin)),{});
        UniValue req; if(!req.read(text)) throw std::runtime_error("invalid JSON request");
        const std::string mode=req["mode"].get_str();
        Recovery recovery; recovery.Load(req);
        UniValue out(UniValue::VOBJ); out.pushKV("consensus_modified",false);
        out.pushKV("search_method","libsecp256k1 public-scalar recovery: P=u1*G once per digest, Q=P+C_b per valid branch; SHA256; strict-DER with nonzero r,s; no consensus code executed");
        if(mode=="screen") {
            // Phase 4 supplies exact digest-round sighashes in bounded batches.
            // Return every syntactic hit; the driver validates its second stage.
            uint64_t count=0,trials=0;
            UniValue hits(UniValue::VARR);
            for(const auto& value:req["digests"].getValues()) {
                const auto raw=Hex(value);
                if(raw.size()!=32) throw std::runtime_error("digest size");
                Hash z; std::copy(raw.begin(),raw.end(),z.begin());
                for(const auto& [b,key]:recovery.Keys(z)) {
                    Hash h; CSHA256().Write(key.data(),key.size()).Finalize(h.data());
                    ++trials;
                    if(StrictDerNonzero(h.data(),h.size())) hits.push_back(Event(count,z,b,key,h));
                }
                ++count;
            }
            out.pushKV("candidates",count); out.pushKV("key_trials",trials);
            out.pushKV("der_passes",uint64_t(hits.size())); out.pushKV("der_pass_events",hits);
            std::cout<<out.write()<<'\n'; return 0;
        }
        if(mode=="vectors") {
            UniValue rows(UniValue::VARR);
            const bool templates=req.exists("sequences");
            CSHA256 state;
            Bytes tail;
            if(templates) {
                state=PrefixState(Hex(req["prefix_hex"]),Hex(req["code_hex"]));
                tail=Hex(req["tail_hex"]);
            }
            for(const auto& value:req[templates?"sequences":"digests"].getValues()) {
                Hash z;
                if(templates) {
                    Bytes suffix; LE(suffix,value.getInt<uint32_t>(),4); Add(suffix,tail); z=Finish(state,suffix);
                } else {
                    const auto raw=Hex(value); if(raw.size()!=32) throw std::runtime_error("digest size");
                    std::copy(raw.begin(),raw.end(),z.begin());
                }
                UniValue row(UniValue::VOBJ); row.pushKV("digest_hex",HexStr(z));
                UniValue keys(UniValue::VARR);
                for(const auto& [b,key]:recovery.Keys(z)) {
                    Hash h;
                    CSHA256().Write(key.data(),key.size()).Finalize(h.data());
                    UniValue k(UniValue::VOBJ); k.pushKV("branch",uint64_t(b));
                    k.pushKV("key_hex",HexStr(key)); k.pushKV("sha256_hex",HexStr(h));
                    k.pushKV("der_pass",StrictDerNonzero(h.data(),h.size()));
                    keys.push_back(k);
                }
                row.pushKV("branches",keys);
                UniValue general(UniValue::VARR);
                for(int recid=0;recid<4;++recid) {
                    const auto key=recovery.General(z,recid);
                    if(!key.empty()) { UniValue g(UniValue::VOBJ); g.pushKV("recid",uint64_t(recid)); g.pushKV("key_hex",HexStr(key)); general.push_back(g); }
                }
                row.pushKV("general_recovery",general); rows.push_back(row);
            }
            out.pushKV("vectors",rows); std::cout<<out.write()<<'\n'; return 0;
        }
        const uint64_t maximum=req["max_candidates"].getInt<uint64_t>();
        const double max_seconds=req["max_seconds"].get_real();
        if(!maximum || !(max_seconds>0)) throw std::runtime_error("invalid search budget");
        if(mode=="benchmark") {
            auto start=Clock::now(); uint64_t count=0,passes=0,trials=0;
            for(;count<maximum;++count) {
                if(count%1024==0 && Seconds(start)>=max_seconds) break;
                Bytes data; LE(data,count,8);
                for(const auto& [b,key]:recovery.Keys(DoubleHash(data))) {
                    Hash h; CSHA256().Write(key.data(),key.size()).Finalize(h.data());
                    ++trials;
                    passes+=StrictDerNonzero(h.data(),h.size());
                }
            }
            out.pushKV("measurement",Rate(count,Seconds(start),"synthetic digest -> recovered keys -> SHA256 DER predicate"));
            out.pushKV("key_trials",trials);
            out.pushKV("der_passes",passes); std::cout<<out.write()<<'\n'; return 0;
        }
        if(mode!="pin") throw std::runtime_error("unknown search mode");
        Bytes prefix=Hex(req["prefix_hex"]),tail=Hex(req["tail_hex"]),code=Hex(req["code_hex"]);
        const uint64_t first=req["counter"].getInt<uint64_t>();
        const bool stop_on_der=req.exists("stop_on_der") && req["stop_on_der"].get_bool();
        const auto pin_state=PrefixState(prefix,code);
        auto start=Clock::now(); uint64_t count=0,passes=0,trials=0;
        bool space_exhausted=false;
        std::string stop_reason="candidate_budget";
        UniValue hits(UniValue::VARR);
        for(;count<maximum;++count) {
            if(count%256==0 && Seconds(start)>=max_seconds) { stop_reason="time_budget"; break; }
            const uint64_t counter=first+count;
            if(counter>=0x80000000ULL) { space_exhausted=true; stop_reason="sequence_space"; break; }
            Bytes suffix; LE(suffix,uint32_t(0x80000000ULL|counter),4); Add(suffix,tail);
            Hash z=Finish(pin_state,suffix);
            for(const auto& [b,key]:recovery.Keys(z)) {
                Hash h; CSHA256().Write(key.data(),key.size()).Finalize(h.data());
                ++trials;
                if(StrictDerNonzero(h.data(),h.size())) {
                    ++passes;
                    if(passes<=16) hits.push_back(Event(counter,z,b,key,h));
                }
            }
            if(stop_on_der && passes) { ++count; stop_reason="der_hit"; break; }
        }
        out.pushKV("found",passes>0); out.pushKV("der_passes",passes); out.pushKV("der_pass_events",hits);
        out.pushKV("key_trials",trials); out.pushKV("stop_reason",stop_reason);
        out.pushKV("clock_check_interval_candidates",uint64_t(256));
        out.pushKV("space_exhausted",space_exhausted);
        out.pushKV("budget_exhausted",!space_exhausted && stop_reason!="der_hit");
        out.pushKV("measurement",Rate(count,Seconds(start),"transaction sequence variants"));
        out.pushKV("first_counter",first); out.pushKV("next_counter",first+count);
        std::cout<<out.write()<<'\n'; return 0;
    } catch(const std::exception& error) {
        std::cerr<<"phase3 search: "<<error.what()<<'\n'; return 2;
    }
}
