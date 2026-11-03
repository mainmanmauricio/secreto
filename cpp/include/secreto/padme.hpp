// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Padme length padding (spec/format.md, "Padding").
#pragma once

#include <cstdint>

namespace secreto {

// Padme(L); Padme(0) == 0.
std::uint64_t padme(std::uint64_t length);

}  // namespace secreto
