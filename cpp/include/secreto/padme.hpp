// Padme length padding (spec/format.md, "Padding").
#pragma once

#include <cstdint>

namespace secreto {

// Padme(L); Padme(0) == 0.
std::uint64_t padme(std::uint64_t length);

}  // namespace secreto
