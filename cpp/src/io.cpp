// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include "secreto/io.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace secreto::io {

namespace {

std::string errstr() { return std::strerror(errno); }

constexpr std::size_t kMaxPassphrase = 1 << 20;

// RAII fd.
struct Fd {
  int fd = -1;
  Fd() = default;
  explicit Fd(int f) : fd(f) {}
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  ~Fd() {
    if (fd >= 0) ::close(fd);
  }
  int release() {
    int f = fd;
    fd = -1;
    return f;
  }
};

void write_all(int fd, ByteView data, const std::string& what) {
  std::size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      fail(kExitIo, "cannot write " + what + ": " + errstr());
    }
    off += static_cast<std::size_t>(n);
  }
}

std::string dir_of(const std::string& path) {
  std::size_t slash = path.rfind('/');
  if (slash == std::string::npos) return ".";
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

}  // namespace

SecretBytes read_fd(int fd) {
  SecretBytes out;
  std::uint8_t buf[65536];
  while (true) {
    ssize_t n = ::read(fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR) continue;
      cleanse(buf, sizeof buf);
      fail(kExitIo, "read error: " + errstr());
    }
    if (n == 0) break;
    out.insert(out.end(), buf, buf + n);
  }
  cleanse(buf, sizeof buf);
  return out;
}

SecretBytes read_input(const std::string& path) {
  if (path.empty() || path == "-") return read_fd(STDIN_FILENO);
  return read_file(path);
}

SecretBytes read_file(const std::string& path) {
  Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (fd.fd < 0) fail(kExitIo, "cannot open " + path + ": " + errstr());
  return read_fd(fd.fd);
}

void warn_if_permissive(const std::string& path, const char* what) {
  struct stat st;
  if (path == "-" || ::stat(path.c_str(), &st) != 0) return;
  if (S_ISREG(st.st_mode) && (st.st_mode & 0077) != 0)
    std::fprintf(stderr, "secreto: warning: %s file %s is group- or world-accessible\n", what,
                 path.c_str());
}

bool stdout_is_tty() { return ::isatty(STDOUT_FILENO) == 1; }

void write_output(const std::string& path, ByteView data) {
  if (path.empty() || path == "-") {
    write_all(STDOUT_FILENO, data, "standard output");
    return;
  }

  struct stat st;
  if (::stat(path.c_str(), &st) == 0 && !S_ISREG(st.st_mode)) {
    // Device, FIFO, ...: write straight through, no rename.
    Fd fd(::open(path.c_str(), O_WRONLY | O_CLOEXEC));
    if (fd.fd < 0) fail(kExitIo, "cannot open " + path + ": " + errstr());
    write_all(fd.fd, data, path);
    return;
  }

  std::string tmpl = dir_of(path) + "/.secreto-tmp-XXXXXX";
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  Fd fd(::mkstemp(buf.data()));  // O_EXCL | 0600
  if (fd.fd < 0) fail(kExitIo, "cannot create temporary file for " + path + ": " + errstr());
  std::string tmp(buf.data());
  try {
    ::fchmod(fd.fd, 0600);
    write_all(fd.fd, data, path);
    if (::fsync(fd.fd) != 0) fail(kExitIo, "cannot sync " + path + ": " + errstr());
    if (::close(fd.release()) != 0) fail(kExitIo, "cannot close " + path + ": " + errstr());
    if (::rename(tmp.c_str(), path.c_str()) != 0)
      fail(kExitIo, "cannot rename into " + path + ": " + errstr());
  } catch (...) {
    ::unlink(tmp.c_str());
    throw;
  }
}

namespace {

// One passphrase from an fd: up to first LF/EOF, strip one trailing CR (of CRLF).
SecretBytes read_passphrase_fd(int fd) {
  SecretBytes pw;
  while (true) {
    std::uint8_t c;
    ssize_t n = ::read(fd, &c, 1);
    if (n < 0) {
      if (errno == EINTR) continue;
      fail(kExitIo, "cannot read passphrase: " + errstr());
    }
    if (n == 0) break;
    if (c == '\n') {
      if (!pw.empty() && pw.back() == '\r') pw.pop_back();
      break;
    }
    pw.push_back(c);
    if (pw.size() > kMaxPassphrase) fail(kExitUsage, "passphrase too long");
  }
  return pw;
}

SecretBytes read_passphrase_tty(const char* prompt) {
  Fd tty(::open("/dev/tty", O_RDWR | O_CLOEXEC));
  if (tty.fd < 0)
    fail(kExitIo, "cannot open /dev/tty for passphrase (set SECRETO_PASSPHRASE_FD)");
  struct termios old_t, new_t;
  if (::tcgetattr(tty.fd, &old_t) != 0) fail(kExitIo, "cannot configure terminal");
  new_t = old_t;
  new_t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
  if (::tcsetattr(tty.fd, TCSAFLUSH, &new_t) != 0) fail(kExitIo, "cannot disable terminal echo");
  write_all(tty.fd, as_bytes(prompt), "terminal");

  SecretBytes pw;
  try {
    pw = read_passphrase_fd(tty.fd);
  } catch (...) {
    ::tcsetattr(tty.fd, TCSAFLUSH, &old_t);
    throw;
  }
  ::tcsetattr(tty.fd, TCSAFLUSH, &old_t);
  write_all(tty.fd, as_bytes("\n"), "terminal");
  return pw;
}

}  // namespace

SecretBytes read_passphrase(bool confirm) {
  if (const char* env = std::getenv("SECRETO_PASSPHRASE_FD")) {
    std::string s(env);
    if (s.empty() || s.size() > 9 || s.find_first_not_of("0123456789") != std::string::npos)
      fail(kExitUsage, "SECRETO_PASSPHRASE_FD must be a decimal file descriptor number");
    int fd = std::atoi(s.c_str());
    struct stat st;
    if (::fstat(fd, &st) != 0) fail(kExitUsage, "SECRETO_PASSPHRASE_FD is not an open descriptor");
    return read_passphrase_fd(fd);
  }
  SecretBytes pw = read_passphrase_tty("Passphrase: ");
  if (confirm) {
    SecretBytes again = read_passphrase_tty("Confirm passphrase: ");
    if (!ct_equal(pw, again)) fail(kExitUsage, "passphrases do not match");
  }
  return pw;
}

}  // namespace secreto::io
