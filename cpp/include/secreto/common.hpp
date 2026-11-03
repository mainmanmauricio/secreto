// Shared basic types: byte buffers, secret-cleansing allocator, errors.
#pragma once

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace secreto {

// Process exit codes (spec/cli.md).
inline constexpr int kExitOk = 0;
inline constexpr int kExitUsage = 1;
inline constexpr int kExitIo = 2;
inline constexpr int kExitNoMatch = 3;
inline constexpr int kExitFormat = 4;
inline constexpr int kExitSignature = 5;

// Wipes `n` bytes at `p` and releases the block (out of line on purpose).
void secure_free(void* p, std::size_t n) noexcept;

// Allocator that wipes memory with OPENSSL_cleanse before releasing it.
template <class T>
struct CleansingAllocator {
  using value_type = T;
  CleansingAllocator() noexcept = default;
  template <class U>
  CleansingAllocator(const CleansingAllocator<U>&) noexcept {}
  T* allocate(std::size_t n) {
    return static_cast<T*>(::operator new(n * sizeof(T)));
  }
  void deallocate(T* p, std::size_t n) noexcept {
    secure_free(p, n * sizeof(T));
  }
  template <class U>
  bool operator==(const CleansingAllocator<U>&) const noexcept {
    return true;
  }
};

using Bytes = std::vector<std::uint8_t>;
using SecretBytes = std::vector<std::uint8_t, CleansingAllocator<std::uint8_t>>;
using ByteView = std::span<const std::uint8_t>;

// Error carrying the process exit code it maps to.
class Error : public std::runtime_error {
 public:
  Error(int code, const std::string& msg) : std::runtime_error(msg), code_(code) {}
  int code() const noexcept { return code_; }

 private:
  int code_;
};

[[noreturn]] inline void fail(int code, const std::string& msg) { throw Error(code, msg); }

// View a string's bytes.
inline ByteView as_bytes(std::string_view s) {
  return ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

inline std::string to_string(ByteView b) {
  return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

// Append helpers.
template <class V>
inline void append(V& dst, ByteView src) {
  dst.insert(dst.end(), src.begin(), src.end());
}
template <class V>
inline void append(V& dst, std::string_view src) {
  append(dst, as_bytes(src));
}

// Wipe a buffer in place.
inline void cleanse(void* p, std::size_t n) { OPENSSL_cleanse(p, n); }
template <class V>
inline void cleanse(V& v) {
  if (!v.empty()) OPENSSL_cleanse(v.data(), v.size() * sizeof(typename V::value_type));
}

// Constant-time equality of equal-length buffers (false on length mismatch).
bool ct_equal(ByteView a, ByteView b);

std::string hex_encode(ByteView b);
// Returns false on odd length / non-hex characters.
bool hex_decode(std::string_view s, Bytes& out);

}  // namespace secreto
