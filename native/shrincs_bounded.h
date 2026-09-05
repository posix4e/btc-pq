#pragma once
#include "shrincs_cost.h"
#include <cstdint>
#include <limits>
#include <span>

struct ShrincsWork {
    bool valid{false};
    bool work_exhausted{false};
    bool sampling_exhausted{false};
    uint64_t compression_blocks{0};
    uint64_t hash_calls{0};
    uint32_t wots_attempts{0};
    uint32_t xof_blocks{0};
    uint32_t pors_auth_nodes{0};
    uint32_t pors_root_height{0};
};

// The optional lower limits support boundary tests. Neither can raise the
// fixed local rules. The opcode never supplies overrides.
ShrincsWork BoundedShrincsVerify(std::span<const unsigned char> message,
    std::span<const unsigned char> signature, std::span<const unsigned char> key,
    uint64_t work_limit = std::numeric_limits<uint64_t>::max(),
    uint32_t xof_limit = btc_pq::SHRINCS_XOF_BLOCK_LIMIT);
