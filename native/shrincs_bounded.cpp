// Standalone B32 verifier, using RAII and checking work before each hash.
#include "shrincs_bounded.h"
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <map>
#include <numeric>
#include <set>
#include <vector>

namespace {
using Bytes = std::span<const unsigned char>;
using Node = std::array<unsigned char, 16>;
using Digest = std::array<unsigned char, 32>;
struct Invalid {};
struct WorkLimit {};
struct SamplingLimit {};

void Put32(unsigned char* out, uint32_t value) {
    for (int i = 3; i >= 0; --i) { out[i] = value & 255; value >>= 8; }
}
uint32_t Bits(Bytes bytes, uint32_t start, uint32_t count) {
    uint32_t result = 0;
    for (uint32_t i = 0; i < count; ++i)
        result = (result << 1) | ((bytes[(start+i)/8] >> (7-(start+i)%8)) & 1);
    return result;
}
bool Equal(Bytes a, Bytes b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

class Verifier {
    SHA256_CTX base;
    Bytes root;
    uint64_t limit;
    uint32_t xof_limit;
public:
    ShrincsWork& work;
    void Charge(uint64_t blocks) {
        if (blocks > limit-work.compression_blocks) { work.work_exhausted = true; throw WorkLimit{}; }
        work.compression_blocks += blocks;
    }
    Verifier(Bytes key, uint64_t bound, uint32_t sampling, ShrincsWork& stats)
        : root(key.subspan(16)), limit(bound), xof_limit(sampling), work(stats) {
        Charge(1);
        const std::array<unsigned char, 48> zero{};
        SHA256_Init(&base);
        SHA256_Update(&base, key.data(), 16);
        SHA256_Update(&base, zero.data(), zero.size());
    }
    Digest Full(uint32_t kind, std::initializer_list<Bytes> pieces,
                uint32_t layer=0, uint32_t tree=0, uint32_t keypair=0, uint32_t a=0, uint32_t b=0) {
        Digest address{};
        Put32(address.data(), layer); Put32(address.data()+12, tree);
        Put32(address.data()+16, kind); Put32(address.data()+20, keypair);
        Put32(address.data()+24, a); Put32(address.data()+28, b);
        size_t bytes = address.size();
        for (Bytes part : pieces) bytes += part.size();
        Charge((bytes+9+63)/64);
        ++work.hash_calls;
        SHA256_CTX ctx = base;
        SHA256_Update(&ctx, address.data(), address.size());
        for (Bytes part : pieces) SHA256_Update(&ctx, part.data(), part.size());
        Digest digest;
        SHA256_Final(digest.data(), &ctx);
        return digest;
    }
    Node H(uint32_t kind, std::initializer_list<Bytes> pieces,
           uint32_t layer=0, uint32_t tree=0, uint32_t keypair=0, uint32_t a=0, uint32_t b=0) {
        const auto full = Full(kind, pieces, layer, tree, keypair, a, b);
        Node result; std::copy_n(full.begin(), 16, result.begin()); return result;
    }
    Node Wots(Bytes sig, Bytes message, bool stateful, uint32_t keypair, uint32_t layer=0, uint32_t tree=0) {
        ++work.wots_attempts;
        Node digest;
        if (stateful) digest = H(4, {sig.first(32), root, message}, layer, tree);
        else { if (message.size() != 16) throw Invalid{}; std::copy_n(message.begin(), 16, digest.begin()); }
        const auto digits = H(stateful ? 3 : 14, {digest, sig.subspan(32, 4)}, layer, tree, keypair);
        if (std::accumulate(digits.begin(), digits.end(), 0) != 2040) throw Invalid{};
        std::array<unsigned char, 256> tips;
        for (uint32_t chain = 0; chain < 16; ++chain) {
            Node node; std::copy_n(sig.begin()+36+chain*16, 16, node.begin());
            for (uint32_t step = digits[chain]; step < 255; ++step)
                node = H(stateful ? 0 : 11, {node}, layer, tree, keypair, chain, step);
            std::copy(node.begin(), node.end(), tips.begin()+chain*16);
        }
        return H(stateful ? 1 : 12, {tips}, layer, tree, keypair);
    }
    bool Compact(Bytes message, Bytes sig) {
        const uint32_t q = (sig.size()-308)/16;
        for (uint32_t candidate = q; candidate <= (q == 210 ? 211 : q); ++candidate) {
            try {
                auto node = Wots(sig.subspan(16, 292), message, true, candidate);
                for (uint32_t i = 0; i < q; ++i) {
                    const auto sibling = sig.subspan(308+i*16, 16);
                    const auto height = candidate <= 210 ? 211-candidate+i : i+1;
                    node = candidate <= 210 && i == 0 ? H(2, {node, sibling}, 0, 0, 0, height)
                                                     : H(2, {sibling, node}, 0, 0, 0, height);
                }
                if (Equal(H(17, {node, sig.first(16)}), root)) return true;
            } catch (const Invalid&) { }
        }
        return false;
    }
    std::pair<std::vector<uint32_t>, uint32_t> Indices(const Digest& digest) {
        std::set<uint32_t> selected;
        std::array<unsigned char, 64> prefix{};
        for (uint32_t counter = 0; counter < xof_limit; ++counter) {
            std::array<unsigned char, 4> encoded; Put32(encoded.data(), counter);
            const auto block = Full(10, {digest, encoded});
            ++work.xof_blocks;
            if (counter < 2) std::copy(block.begin(), block.end(), prefix.begin()+counter*32);
            for (uint32_t i = 0; i < 15 && selected.size() < 11; ++i) {
                const auto candidate = Bits(block, i*17, 17);
                if (candidate < 109571) selected.insert(candidate);
            }
            // Preserve the pinned verifier's extra block after the fixed prefix.
            if (selected.size() == 11 && counter >= 2)
                return {{selected.begin(), selected.end()}, Bits(prefix, 424, 32)};
        }
        work.sampling_exhausted = true; throw SamplingLimit{};
    }
    Node Pors(Bytes sig, const std::vector<uint32_t>& indices, uint32_t tree) {
        using Position = std::pair<uint32_t, uint32_t>;
        std::map<Position, Node> nodes;
        for (uint32_t i = 0; i < indices.size(); ++i) {
            const auto index = indices[i];
            const Position position = index < 88070 ? Position{0,index} : Position{1,index-44035};
            nodes.emplace(position, H(6, {sig.subspan(32+i*16,16)}, 0, tree, 0, 0, index));
        }
        uint32_t cursor = 32+16*11;
        for (uint32_t level = 0; level < 17; ++level) {
            std::vector<uint32_t> current;
            for (const auto& [position, node] : nodes) if (position.first == level) current.push_back(position.second);
            for (uint32_t index : current) {
                auto found = nodes.find({level,index});
                if (found == nodes.end()) continue;
                const Node node = found->second; nodes.erase(found);
                Node sibling;
                found = nodes.find({level,index^1});
                if (found != nodes.end()) { sibling = found->second; nodes.erase(found); }
                else {
                    if (cursor+16 > sig.size()) throw Invalid{};
                    std::copy_n(sig.begin()+cursor, 16, sibling.begin()); cursor += 16;
                    ++work.pors_auth_nodes;
                }
                const auto parent = index%2 == 0 ? H(7, {node,sibling}, 0, tree, 0, level+1, index/2)
                                                 : H(7, {sibling,node}, 0, tree, 0, level+1, index/2);
                if (!nodes.emplace(Position{level+1,index/2}, parent).second) throw Invalid{};
            }
            if (nodes.size() == 1 && nodes.begin()->first == Position{level+1,0}) {
                work.pors_root_height = level+1; break;
            }
        }
        if (!work.pors_root_height || std::any_of(sig.begin()+cursor, sig.end(), [](auto b){ return b != 0; })) throw Invalid{};
        return H(8, {nodes.begin()->second}, 0, tree);
    }
    bool Recovery(Bytes message, Bytes sig) {
        const auto pors = sig.subspan(16,1984);
        auto [indices, tree] = Indices(Full(15, {pors.first(32), root, message}));
        auto node = Pors(pors, indices, tree);
        for (uint32_t layer = 0; layer < 4; ++layer) {
            uint32_t leaf = tree & 255; tree >>= 8;
            const auto xmss = sig.subspan(2000+layer*420,420);
            node = Wots(xmss.first(292), node, false, leaf, layer, tree);
            for (uint32_t height = 1; height <= 8; ++height) {
                const auto sibling = xmss.subspan(292+(height-1)*16,16);
                const bool right = leaf%2; leaf >>= 1;
                node = right ? H(13, {sibling,node}, layer, tree, 0, height, leaf)
                             : H(13, {node,sibling}, layer, tree, 0, height, leaf);
            }
        }
        return Equal(H(17, {sig.first(16),node}), root);
    }
};
}

ShrincsWork BoundedShrincsVerify(Bytes message, Bytes signature, Bytes key, uint64_t limit, uint32_t sampling) {
    ShrincsWork work;
    const auto bound = btc_pq::ShrincsWorkBound(signature.size(), message.size());
    if (key.size() != 32 || !bound) return work;
    try {
        Verifier verifier(key, std::min(limit,bound), std::min(sampling,btc_pq::SHRINCS_XOF_BLOCK_LIMIT), work);
        work.valid = signature.size() == 3680 ? verifier.Recovery(message, signature) : verifier.Compact(message, signature);
    } catch (const Invalid&) { }
      catch (const WorkLimit&) { }
      catch (const SamplingLimit&) { }
    return work;
}
