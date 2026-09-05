// Public-data CPU search for the separately patched regtest experiment.
#include <script/btc_pq_toy.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <numeric>
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
    else { a.push_back(254); LE(a,n,4); }
}
static Hash DoubleHash(const Bytes& bytes) {
    Hash h; CSHA256().Write(bytes.data(),bytes.size()).Finalize(h.data());
    CSHA256().Write(h.data(),h.size()).Finalize(h.data()); return h;
}
static Hash Finish(CSHA256 state,const Bytes& tail) {
    Hash h; state.Write(tail.data(),tail.size()).Finalize(h.data());
    CSHA256().Write(h.data(),h.size()).Finalize(h.data()); return h;
}

struct PublicRecovery {
    secp256k1_context* ctx{secp256k1_context_create(SECP256K1_CONTEXT_NONE)};
    Bytes inverse{ParseHex("1dd887b3eaf153260a95e8b9fd31f60ac115d26ccbe1f572c0b8d7a6dec520fe")};
    Bytes order{ParseHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};
    secp256k1_ecdsa_recoverable_signature fixed;
    PublicRecovery() {
        Bytes compact=ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        compact.resize(64); compact[63]=1;
        if(!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&fixed,compact.data(),0)) throw std::runtime_error("fixed signature");
    }
    ~PublicRecovery() { secp256k1_context_destroy(ctx); }
    Bytes Serialize(const secp256k1_pubkey& pub) {
        Bytes key(33); size_t n=33;
        if(!secp256k1_ec_pubkey_serialize(ctx,key.data(),&n,&pub,SECP256K1_EC_COMPRESSED)) throw std::runtime_error("serialize pubkey");
        return key;
    }
    Bytes Recover(const Hash& z) {
        secp256k1_pubkey pub;
        if(!secp256k1_ecdsa_recover(ctx,&pub,&fixed,z.data())) return {};
        return Serialize(pub);
    }
    Bytes Key(const Hash& z) {
        // Q=((1-z)/r)G for the fixed public R=G,s=1 signature. These scalars
        // are public computations, not wallet keys. Includes z>=n and z=0.
        Hash scalar=z;
        if(!std::lexicographical_compare(scalar.begin(),scalar.end(),order.begin(),order.end())) {
            int borrow=0;
            for(int j=31;j>=0;--j) { int v=int(scalar[j])-order[j]-borrow; scalar[j]=v&255; borrow=v<0; }
        }
        Hash one{}; one[31]=1;
        if(std::all_of(scalar.begin(),scalar.end(),[](unsigned char c){return c==0;})) scalar=one;
        else {
            if(!secp256k1_ec_seckey_negate(ctx,scalar.data()) ||
               !secp256k1_ec_seckey_tweak_add(ctx,scalar.data(),one.data())) return {};
        }
        if(!secp256k1_ec_seckey_tweak_mul(ctx,scalar.data(),inverse.data())) return {};
        secp256k1_pubkey pub;
        if(!secp256k1_ec_pubkey_create(ctx,&pub,scalar.data())) return {};
        return Serialize(pub);
    }
};

static UniValue Hit(const Hash& z,const Bytes& key,const Bytes& sig,unsigned bits) {
    UniValue v(UniValue::VOBJ);
    v.pushKV("digest_hex",HexStr(z)); v.pushKV("key_hex",HexStr(key));
    v.pushKV("hash_hex",HexStr(BtcPqToyHash(key,bits))); v.pushKV("signature_hex",HexStr(sig));
    return v;
}
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
static CSHA256 PrefixState(const Bytes& prefix,const Bytes& code) {
    Bytes before=prefix; Compact(before,code.size()); Add(before,code);
    return CSHA256().Write(before.data(),before.size());
}

int main() {
    try {
        std::string text((std::istreambuf_iterator<char>(std::cin)),{});
        UniValue req; if(!req.read(text)) throw std::runtime_error("invalid JSON request");
        const std::string mode=req["mode"].get_str();
        const unsigned bits=req["bits"].getInt<unsigned>();
        if(bits<1 || bits>24) throw std::runtime_error("bits outside 1..24");
        PublicRecovery recovery;
        UniValue out(UniValue::VOBJ); out.pushKV("consensus_modified",true); out.pushKV("qsb_exact_reproduction",false);
        out.pushKV("search_method","libsecp256k1 public-scalar fixed-signature recovery; compressed branch R=G");
        if(mode=="vectors") {
            UniValue rows(UniValue::VARR);
            for(const auto& value:req["digests"].getValues()) {
                const auto raw=Hex(value); if(raw.size()!=32) throw std::runtime_error("digest size");
                Hash z; std::copy(raw.begin(),raw.end(),z.begin());
                const auto key=recovery.Key(z), reference=recovery.Recover(z);
                Bytes sig; const bool pass=BtcPqToySignature(key,bits,sig);
                auto row=Hit(z,key,sig,bits); row.pushKV("general_recovery_key_hex",HexStr(reference)); row.pushKV("passes",pass);
                rows.push_back(row);
            }
            out.pushKV("vectors",rows); std::cout<<out.write()<<'\n'; return 0;
        }
        const uint64_t maximum=req["max_candidates"].getInt<uint64_t>();
        const double max_seconds=req["max_seconds"].get_real();
        if(!maximum || !(max_seconds>0)) throw std::runtime_error("invalid search budget");
        if(mode=="benchmark") {
            auto start=Clock::now(); uint64_t count=0,hits=0;
            for(;count<maximum;++count) {
                if(count%1024==0 && Seconds(start)>=max_seconds) break;
                Bytes data; LE(data,count,8); auto key=recovery.Key(DoubleHash(data)); Bytes sig;
                hits+=BtcPqToySignature(key,bits,sig);
            }
            out.pushKV("measurement",Rate(count,Seconds(start),"synthetic digest -> public key -> toy hash predicate"));
            out.pushKV("hits",hits); std::cout<<out.write()<<'\n'; return 0;
        }
        if(mode!="pin" && mode!="subset" && mode!="frozen") throw std::runtime_error("unknown search mode");
        Bytes prefix=Hex(req["prefix_hex"]),tail=Hex(req["tail_hex"]),code=Hex(req["code_hex"]);
        std::vector<std::pair<size_t,size_t>> spans;
        for(const auto& span:req["spans"].getValues()) spans.emplace_back(span[0].getInt<size_t>(),span[1].getInt<size_t>());
        unsigned t=req["selections"].getInt<unsigned>();
        if(spans.size()>64 || !t || t>spans.size()) throw std::runtime_error("invalid table dimensions");
        const uint64_t first=req["counter"].getInt<uint64_t>();
        std::vector<unsigned> selected(t); std::iota(selected.begin(),selected.end(),0);
        if(mode=="frozen") {
            selected.clear(); for(const auto& i:req["frozen_indices"].getValues()) selected.push_back(i.getInt<unsigned>());
            if(selected.size()!=t || !std::is_sorted(selected.begin(),selected.end()) ||
               std::adjacent_find(selected.begin(),selected.end())!=selected.end()) throw std::runtime_error("invalid frozen subset");
        }
        const auto pin_state=PrefixState(prefix,code);
        CSHA256 frozen_state;
        if(mode=="frozen") frozen_state=PrefixState(prefix,Removed(code,spans,selected));
        auto start=Clock::now(); uint64_t count=0,digest_count=0; double digest_seconds=0;
        bool found=false,space_exhausted=false;
        for(;count<maximum;) {
            if(count%1024==0 && Seconds(start)>=max_seconds) break;
            const uint64_t counter=first+count;
            if(mode!="subset" && counter>=0x80000000ULL) { space_exhausted=true; break; }
            const uint32_t sequence=mode=="subset"?req["sequence"].getInt<uint32_t>():uint32_t(0x80000000ULL|counter);
            Bytes suffix; LE(suffix,sequence,4); Add(suffix,tail);
            Hash z=mode=="subset"?Finish(PrefixState(prefix,Removed(code,spans,selected)),suffix):Finish(pin_state,suffix);
            auto key=recovery.Key(z); Bytes sig;
            bool pass=BtcPqToySignature(key,bits,sig); ++count;
            if(pass && mode=="frozen") {
                auto dstart=Clock::now(); auto dz=Finish(frozen_state,suffix); auto dk=recovery.Key(dz); Bytes ds;
                const bool digest_pass=BtcPqToySignature(dk,bits,ds); ++digest_count; digest_seconds+=Seconds(dstart);
                if(digest_pass) out.pushKV("digest_hit",Hit(dz,dk,ds,bits));
                pass=digest_pass;
            }
            if(pass) {
                found=true; out.pushKV("hit",Hit(z,key,sig,bits)); out.pushKV("sequence",uint64_t(sequence));
                out.pushKV("winning_counter",counter);
                UniValue indices(UniValue::VARR); for(auto i:selected) indices.push_back(uint64_t(i));
                if(mode!="pin") out.pushKV("selected_indices",indices);
                break;
            }
            if(mode=="subset") {
                int j=t-1; while(j>=0 && selected[j]==spans.size()-t+j) --j;
                if(j<0) { space_exhausted=true; break; }
                ++selected[j]; for(unsigned k=j+1;k<t;++k) selected[k]=selected[k-1]+1;
            }
        }
        const double elapsed=Seconds(start);
        out.pushKV("found",found); out.pushKV("space_exhausted",space_exhausted);
        out.pushKV("budget_exhausted",!found && !space_exhausted);
        out.pushKV("measurement",Rate(count,elapsed,mode=="subset"?"distinct subsets":"transaction sequence variants"));
        if(mode=="frozen") {
            out.pushKV("pinning",Rate(count,elapsed-digest_seconds,"transaction sequence variants"));
            out.pushKV("frozen_digest",Rate(digest_count,digest_seconds,"fixed-subset checks after passing pinning"));
        }
        std::cout<<out.write()<<'\n'; return 0;
    } catch(const std::exception& error) {
        std::cerr<<"toy search: "<<error.what()<<'\n'; return 2;
    }
}
