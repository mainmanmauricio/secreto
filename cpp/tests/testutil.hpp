// Minimal test helpers: CHECK macros, file reading, hex, and a tiny JSON parser.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "secreto/common.hpp"

namespace testutil {

inline int g_failures = 0;
inline int g_checks = 0;

#define CHECK(cond)                                                              \
  do {                                                                           \
    ++testutil::g_checks;                                                        \
    if (!(cond)) {                                                               \
      ++testutil::g_failures;                                                    \
      std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                            \
  } while (0)

#define CHECK_MSG(cond, msg)                                                     \
  do {                                                                           \
    ++testutil::g_checks;                                                        \
    if (!(cond)) {                                                               \
      ++testutil::g_failures;                                                    \
      std::fprintf(stderr, "%s:%d: CHECK failed: %s (%s)\n", __FILE__, __LINE__, #cond, \
                   std::string(msg).c_str());                                    \
    }                                                                            \
  } while (0)

// Expect `expr` to throw secreto::Error with the given exit code.
#define CHECK_THROWS_CODE(expr, expected_code)                                   \
  do {                                                                           \
    ++testutil::g_checks;                                                        \
    int got_code_ = -1;                                                          \
    try {                                                                        \
      (void)(expr);                                                              \
    } catch (const secreto::Error& e_) {                                         \
      got_code_ = e_.code();                                                     \
    } catch (...) {                                                              \
      got_code_ = -2;                                                            \
    }                                                                            \
    if (got_code_ != (expected_code)) {                                          \
      ++testutil::g_failures;                                                    \
      std::fprintf(stderr, "%s:%d: expected exit code %d from `%s`, got %d\n",   \
                   __FILE__, __LINE__, (expected_code), #expr, got_code_);       \
    }                                                                            \
  } while (0)

inline int finish(const char* name) {
  if (g_failures != 0) {
    std::fprintf(stderr, "%s: %d of %d checks FAILED\n", name, g_failures, g_checks);
    return 1;
  }
  std::printf("%s: all %d checks passed\n", name, g_checks);
  return 0;
}

inline secreto::Bytes unhex(const std::string& s) {
  secreto::Bytes b;
  if (!secreto::hex_decode(s, b)) {
    std::fprintf(stderr, "bad hex in test data\n");
    std::abort();
  }
  return b;
}

inline std::string slurp(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    std::fprintf(stderr, "cannot open %s\n", path.c_str());
    std::abort();
  }
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

inline secreto::ByteView view(const std::string& s) { return secreto::as_bytes(s); }

// ------------------------------------------------------------------- JSON --

struct Json {
  enum Type { Null, Bool, Number, String, Array, Object } type = Null;
  bool b = false;
  std::int64_t num = 0;
  std::string str;
  std::vector<Json> arr;
  std::map<std::string, Json> obj;

  const Json& at(const std::string& k) const {
    auto it = obj.find(k);
    if (it == obj.end()) throw std::runtime_error("missing key " + k);
    return it->second;
  }
  bool has(const std::string& k) const { return obj.count(k) != 0; }
};

class JsonParser {
 public:
  explicit JsonParser(const std::string& s) : s_(s) {}
  Json parse() {
    Json v = value();
    ws();
    if (i_ != s_.size()) throw std::runtime_error("trailing JSON data");
    return v;
  }

 private:
  const std::string& s_;
  std::size_t i_ = 0;

  void ws() {
    while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\n' || s_[i_] == '\t' || s_[i_] == '\r'))
      ++i_;
  }
  char peek() {
    ws();
    if (i_ >= s_.size()) throw std::runtime_error("unexpected end of JSON");
    return s_[i_];
  }
  void expect(char c) {
    if (peek() != c) throw std::runtime_error(std::string("expected ") + c);
    ++i_;
  }
  Json value() {
    char c = peek();
    Json v;
    if (c == '{') {
      v.type = Json::Object;
      ++i_;
      if (peek() == '}') {
        ++i_;
        return v;
      }
      while (true) {
        std::string k = string();
        expect(':');
        v.obj[k] = value();
        if (peek() == ',') {
          ++i_;
          continue;
        }
        expect('}');
        return v;
      }
    }
    if (c == '[') {
      v.type = Json::Array;
      ++i_;
      if (peek() == ']') {
        ++i_;
        return v;
      }
      while (true) {
        v.arr.push_back(value());
        if (peek() == ',') {
          ++i_;
          continue;
        }
        expect(']');
        return v;
      }
    }
    if (c == '"') {
      v.type = Json::String;
      v.str = string();
      return v;
    }
    if (s_.compare(i_, 4, "true") == 0) {
      i_ += 4;
      v.type = Json::Bool;
      v.b = true;
      return v;
    }
    if (s_.compare(i_, 5, "false") == 0) {
      i_ += 5;
      v.type = Json::Bool;
      return v;
    }
    if (s_.compare(i_, 4, "null") == 0) {
      i_ += 4;
      return v;
    }
    std::size_t j = i_;
    if (s_[j] == '-') ++j;
    while (j < s_.size() && s_[j] >= '0' && s_[j] <= '9') ++j;
    if (j == i_) throw std::runtime_error("bad JSON value");
    v.type = Json::Number;
    v.num = std::stoll(s_.substr(i_, j - i_));
    i_ = j;
    return v;
  }
  std::string string() {
    expect('"');
    std::string out;
    while (true) {
      if (i_ >= s_.size()) throw std::runtime_error("unterminated JSON string");
      char c = s_[i_++];
      if (c == '"') return out;
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      char e = s_[i_++];
      switch (e) {
        case 'n': out.push_back('\n'); break;
        case 't': out.push_back('\t'); break;
        case 'r': out.push_back('\r'); break;
        case 'u': {
          unsigned cp = static_cast<unsigned>(std::stoul(s_.substr(i_, 4), nullptr, 16));
          i_ += 4;
          if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
          } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          } else {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          }
          break;
        }
        default: out.push_back(e);  // \" \\ \/
      }
    }
  }
};

inline Json load_json(const std::string& path) {
  std::string text = slurp(path);
  return JsonParser(text).parse();
}

}  // namespace testutil
