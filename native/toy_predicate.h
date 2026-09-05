// EXPERIMENTAL CONSENSUS, REGTEST ONLY. Not RIPEMD160 or a Bitcoin opcode.
// This file is shared by the experimental interpreter and the CPU searcher.
#ifndef BTC_PQ_TOY_PREDICATE_H
#define BTC_PQ_TOY_PREDICATE_H
#include <crypto/sha256.h>
#include <array>
#include <cstdint>
#include <vector>

inline std::array<unsigned char,32> BtcPqToyHash(const std::vector<unsigned char>& key, unsigned bits)
{
    constexpr unsigned char domain[] = "BTC-PQ-TOY-H2S-v1";
    const unsigned char b = bits;
    std::array<unsigned char,32> h;
    CSHA256().Write(domain,sizeof(domain)-1).Write(&b,1).Write(key.data(),key.size()).Finalize(h.data());
    return h;
}

inline bool BtcPqToySignature(const std::vector<unsigned char>& key, unsigned bits, std::vector<unsigned char>& sig)
{
    sig.clear();
    if (bits < 1 || bits > 24 || key.size() != 33 || (key[0] != 2 && key[0] != 3)) return false;
    const auto h = BtcPqToyHash(key,bits);
    for (unsigned i = 0; i < bits; ++i) if (h[i/8] & (0x80 >> (i%8))) return false;
    constexpr unsigned char domain[] = "BTC-PQ-TOY-S-v1";
    std::array<unsigned char,32> s_hash;
    CSHA256().Write(domain,sizeof(domain)-1).Write(h.data(),h.size()).Finalize(s_hash.data());
    // s = 1 + BE(first 16 bytes), always a nonzero secp256k1 scalar.
    std::vector<unsigned char> s{0};
    s.insert(s.end(),s_hash.begin(),s_hash.begin()+16);
    for (int i = 16; i >= 0; --i) if (++s[i] != 0) break;
    while (s.size() > 1 && s[0] == 0) s.erase(s.begin());
    if (s[0] & 0x80) s.insert(s.begin(),0);
    // r=2 has a valid curve recovery point; SIGHASH_ALL stays fixed at 01.
    sig = {0x30,static_cast<unsigned char>(5+s.size()),0x02,0x01,0x02,0x02,static_cast<unsigned char>(s.size())};
    sig.insert(sig.end(),s.begin(),s.end());
    sig.push_back(1);
    return true;
}
#endif
