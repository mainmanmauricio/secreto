// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include "secreto/padme.hpp"

#include <bit>

namespace secreto {

static unsigned floor_log2(std::uint64_t v) {
  return 63u - static_cast<unsigned>(std::countl_zero(v));
}

std::uint64_t padme(std::uint64_t length) {
  if (length == 0) return 0;
  unsigned e = floor_log2(length);
  unsigned s = (e == 0) ? 0u : floor_log2(e) / 2;
  std::uint64_t mask = (std::uint64_t{1} << (e - s)) - 1;
  return (length + mask) & ~mask;
}

}  // namespace secreto
