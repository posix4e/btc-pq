#pragma once
#include <cstdint>
#include <span>
#include <vector>

// Keep upstream's hash.h / namespace imports out of Bitcoin Core translation units.
bool DemoShrincsVerify(std::span<const unsigned char> message,
                       std::span<const unsigned char> signature,
                       std::span<const unsigned char> public_key);
