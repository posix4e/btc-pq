#include "shrincs_bridge.h"
#include <shrincs.h>

bool DemoShrincsVerify(std::span<const unsigned char> message,
                       std::span<const unsigned char> signature,
                       std::span<const unsigned char> public_key)
{
    using namespace Parameters;
    // Upstream's generic entry point dispatches by size but does not establish
    // these bounds before reading raw pointers. Validate the exact B32 shapes.
    static_assert(N == 16 && HSF == 210 && SL_SIZE == 3680);
    const auto size = signature.size();
    const bool stateful = size >= N + WOTS_SIGN_LEN + N && size <= MAX_SF_SIZE &&
                          (size - N - WOTS_SIGN_LEN) % N == 0;
    if (public_key.size() != 2*N || (!stateful && size != SL_SIZE)) return false;
    SHRINCS::PublicKey pk;
    pk.seed.assign(public_key.begin(), public_key.begin()+N);
    pk.root.assign(public_key.begin()+N, public_key.end());
    try {
        return SHRINCS::shrincs_verify({message.begin(), message.end()}, signature.data(), size, pk);
    } catch (...) {
        return false;
    }
}
