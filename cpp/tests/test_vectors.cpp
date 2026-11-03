// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Runs every vectors/testkit/*.vec file, either through the library
// (default) or through the `secreto` binary (--cli PATH).
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "secreto/format.hpp"
#include "secreto/keys.hpp"
#include "testutil.hpp"

using namespace secreto;
using namespace testutil;
namespace fs = std::filesystem;

struct Vec {
  std::string name;
  std::string expect;
  std::vector<std::string> identities;
  std::string passphrase;
  bool has_passphrase = false;
  std::string verify;
  std::string payload_hex;
  bool has_payload = false;
  std::string body;
};

static Vec load_vec(const fs::path& p) {
  std::string raw = slurp(p.string());
  Vec v;
  v.name = p.filename().string();
  std::size_t split = raw.find("\n\n");
  if (split == std::string::npos) {
    std::fprintf(stderr, "%s: no metadata separator\n", v.name.c_str());
    std::abort();
  }
  std::string meta = raw.substr(0, split);
  v.body = raw.substr(split + 2);
  std::size_t pos = 0;
  while (pos <= meta.size()) {
    std::size_t nl = meta.find('\n', pos);
    std::string line = meta.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
    pos = (nl == std::string::npos) ? meta.size() + 1 : nl + 1;
    std::size_t colon = line.find(": ");
    std::string key = line.substr(0, colon);
    std::string val = colon == std::string::npos ? "" : line.substr(colon + 2);
    if (line.empty()) continue;
    if (key == "expect") v.expect = val;
    else if (key == "identity") v.identities.push_back(val);
    else if (key == "passphrase") { v.passphrase = val; v.has_passphrase = true; }
    else if (key == "verify") v.verify = val;
    else if (key == "payload") { v.payload_hex = val; v.has_payload = true; }
    else if (key == "armored") { /* informational */ }
    else {
      std::fprintf(stderr, "%s: unknown metadata key '%s'\n", v.name.c_str(), key.c_str());
      std::abort();
    }
  }
  return v;
}

static int expected_exit(const std::string& e) {
  if (e == "success") return kExitOk;
  if (e == "no-match") return kExitNoMatch;
  if (e == "header-failure" || e == "payload-failure") return kExitFormat;
  if (e == "signature-failure") return kExitSignature;
  std::fprintf(stderr, "unknown expectation %s\n", e.c_str());
  std::abort();
}

// ---------------------------------------------------------- library mode --

static void run_library(const Vec& v) {
  DecryptOptions o;
  for (const std::string& id : v.identities) o.identities.push_back(keys::identity_from_bech32(id));
  if (v.has_passphrase) o.passphrase = SecretBytes(v.passphrase.begin(), v.passphrase.end());
  if (!v.verify.empty()) o.verify_key = keys::signer_public_from_bech32(v.verify);

  int code = kExitOk;
  DecryptResult r;
  try {
    r = decrypt(view(v.body), o);
  } catch (const Error& e) {
    code = e.code();
  }
  CHECK_MSG(code == expected_exit(v.expect),
            v.name + ": expected exit " + std::to_string(expected_exit(v.expect)) + ", got " +
                std::to_string(code));
  if (v.expect == "success" && code == kExitOk) {
    CHECK_MSG(hex_encode(r.content) == v.payload_hex, v.name + ": payload mismatch");
  }
}

// -------------------------------------------------------------- CLI mode --

static std::string shell_quote(const std::string& s) { return "'" + s + "'"; }

static void write_file(const fs::path& p, const std::string& data) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
}

static void run_cli(const Vec& v, const std::string& bin, const fs::path& dir) {
  write_file(dir / "in.bin", v.body);
  std::string cmd = "SECRETO_PASSPHRASE_FD=3 " + shell_quote(bin) + " -d";
  for (std::size_t i = 0; i < v.identities.size(); ++i) {
    fs::path idf = dir / ("id" + std::to_string(i) + ".txt");
    write_file(idf, v.identities[i] + "\n");
    fs::permissions(idf, fs::perms::owner_read | fs::perms::owner_write);
    cmd += " -i " + shell_quote(idf.string());
  }
  if (v.has_passphrase) {
    write_file(dir / "pass.txt", v.passphrase + "\n");
    cmd += " -p";
  }
  if (!v.verify.empty()) cmd += " --verify " + shell_quote(v.verify);
  fs::path out = dir / "out.bin";
  fs::remove(out);
  cmd += " -o " + shell_quote(out.string()) + " " + shell_quote((dir / "in.bin").string());
  cmd += " 3<" + shell_quote((dir / (v.has_passphrase ? "pass.txt" : "in.bin")).string());
  cmd += " 2>/dev/null";

  int status = std::system(cmd.c_str());
  int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

  // Without any credential the CLI is a usage error (spec/cli.md), not "no match".
  int want = expected_exit(v.expect);
  if (v.identities.empty() && !v.has_passphrase) want = kExitUsage;
  CHECK_MSG(code == want, v.name + ": expected exit " + std::to_string(want) + ", got " +
                              std::to_string(code));
  if (code != kExitOk) {
    CHECK_MSG(!fs::exists(out), v.name + ": output file exists after failure");
    // No temp files left behind.
    for (const auto& e : fs::directory_iterator(dir))
      CHECK_MSG(e.path().filename().string().rfind(".secreto-tmp-", 0) != 0,
                v.name + ": stale temp file");
  } else if (v.expect == "success") {
    CHECK_MSG(hex_encode(view(slurp(out.string()))) == v.payload_hex, v.name + ": payload mismatch");
  }
}

int main(int argc, char** argv) {
  std::string cli_bin;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--cli" && i + 1 < argc) cli_bin = argv[++i];
    else {
      std::fprintf(stderr, "usage: test_vectors [--cli PATH-TO-secreto]\n");
      return 2;
    }
  }

  fs::path dir = fs::path(SECRETO_VECTORS_DIR) / "testkit";
  std::vector<fs::path> files;
  for (const auto& e : fs::directory_iterator(dir))
    if (e.path().extension() == ".vec") files.push_back(e.path());
  std::sort(files.begin(), files.end());
  CHECK(!files.empty());

  fs::path tmp;
  if (!cli_bin.empty()) {
    std::string tmpl = (fs::current_path() / "vec-tmp-XXXXXX").string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (::mkdtemp(buf.data()) == nullptr) {
      std::fprintf(stderr, "cannot create temp dir\n");
      return 2;
    }
    tmp = buf.data();
  }

  try {
    for (const fs::path& f : files) {
      Vec v = load_vec(f);
      if (cli_bin.empty()) run_library(v);
      else run_cli(v, cli_bin, tmp);
    }
  } catch (const std::exception& e) {
    std::fprintf(stderr, "exception: %s\n", e.what());
    if (!tmp.empty()) fs::remove_all(tmp);
    return 1;
  }
  if (!tmp.empty()) fs::remove_all(tmp);
  std::printf("ran %zu vectors (%s)\n", files.size(), cli_bin.empty() ? "library" : "cli");
  return finish("test_vectors");
}
