// File / stream / passphrase I/O helpers for the command-line programs.
#pragma once

#include <string>

#include "secreto/common.hpp"

namespace secreto::io {

// Read everything from an open file descriptor. Throws Error(kExitIo).
SecretBytes read_fd(int fd);

// Read a path; "-" (or empty) means stdin.
SecretBytes read_input(const std::string& path);

// Read a text file (key / recipient file). Throws Error(kExitIo).
SecretBytes read_file(const std::string& path);

// Print a warning on stderr if `path` is group- or world-accessible.
void warn_if_permissive(const std::string& path, const char* what);

// Write `data` to `path` ("-" or empty = stdout). For files: temp file in the
// same directory (O_EXCL, 0600), fsync, rename; unlinked on failure. Special
// (non-regular) targets are written directly.
void write_output(const std::string& path, ByteView data);

bool stdout_is_tty();

// Passphrase from SECRETO_PASSPHRASE_FD, else /dev/tty with echo disabled
// (twice, requiring equality, when `confirm`).
SecretBytes read_passphrase(bool confirm);

}  // namespace secreto::io
