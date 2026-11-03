# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Padmé length padding (spec/format.md, *Padding*)."""


def padme(length: int) -> int:
    if length < 0:
        raise ValueError("negative length")
    if length <= 1:
        return length
    e = length.bit_length() - 1
    s = (e.bit_length() - 1) // 2 if e >= 1 else 0
    mask = (1 << (e - s)) - 1
    return (length + mask) & ~mask
