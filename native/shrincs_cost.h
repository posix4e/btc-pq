#pragma once
#include <cstddef>
#include <cstdint>

namespace btc_pq {
// Local B32 validation rules. A unit of Tapscript validation weight buys at
// most eight SHA256 compression blocks; charge the entire bound up front.
inline constexpr uint32_t SHRINCS_XOF_BLOCK_LIMIT = 64;
inline constexpr uint32_t SHRINCS_BLOCKS_PER_WEIGHT = 8;

constexpr uint64_t ShrincsWorkBound(size_t size, size_t message_bytes = 32) {
    if (message_bytes > 65536) return 0;
    const uint64_t message_blocks = (32 + 32 + 16 + message_bytes + 9 + 63)/64;
    if (size == 3680) {
        // Prefix; message; 64 XOF blocks; 11 leaves; <=121 PORS parents;
        // PORS key; four WOTS/XMSS layers; final combined root.
        return 1 + message_blocks + 2*SHRINCS_XOF_BLOCK_LIMIT + 11 + 2*121 + 1 + 4*2062 + 2;
    }
    if (size < 324 || size > 3668 || (size-308)%16 != 0) return 0;
    const uint64_t q = (size-308)/16;
    const uint64_t attempts = q == 210 ? 2 : 1;
    // Prefix shared between attempts; each candidate checks message, checksum,
    // 2040 chain steps, WOTS key, q tree parents, and final root.
    return 1 + attempts*(message_blocks + 1 + 2040 + 5 + 2*q + 2);
}

constexpr int64_t ShrincsValidationWeight(size_t size) {
    return (ShrincsWorkBound(size) + SHRINCS_BLOCKS_PER_WEIGHT-1)/SHRINCS_BLOCKS_PER_WEIGHT;
}
static_assert(ShrincsWorkBound(324) == 2053);
static_assert(ShrincsWorkBound(3668) == 4941);
static_assert(ShrincsWorkBound(3680) == 8635);
}
