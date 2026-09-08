#pragma once

#include <charconv>
#include <climits>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

inline uint64_t parse_u64(std::string_view text, int base = 0) {
    const std::string original(text);
    auto invalid = [&]() -> uint64_t {
        throw std::invalid_argument("invalid unsigned integer: '" + original + "'");
    };
    if (text.empty() || text.front() == '-' || text.front() == '+') return invalid();
    if (base == 0) {
        base = 10;
        if (text.size() > 1 && text.front() == '0') {
            base = 8;
            if (text[1] == 'x' || text[1] == 'X') {
                base = 16;
                text.remove_prefix(2);
            }
        }
    }
    uint64_t value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (result.ec != std::errc() || result.ptr != text.data() + text.size())
        return invalid();
    return value;
}

inline int parse_int(std::string_view text) {
    uint64_t value = parse_u64(text, 10);
    if (value > INT_MAX)
        throw std::invalid_argument("integer out of range: '" + std::string(text) + "'");
    return int(value);
}
