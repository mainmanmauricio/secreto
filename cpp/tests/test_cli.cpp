// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// CLI integration tests: drives the `secreto` and `secreto-keygen` binaries.
// usage: test_cli PATH-TO-secreto PATH-TO-secreto-keygen
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "testutil.hpp"

using namespace secreto;
using namespace testutil;
namespace fs = std::filesystem;

static std::string g_secreto, g_keygen;
static fs::path g_dir;

static std::string q(const fs::path& p) { return "'" + p.string() + "'"; }
static fs::path P(const std::string& name) { return g_dir / name; }

static int sh(const std::string& cmd) {
  int status = std::system(cmd.c_str());
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run(const std::string& args, const std::string& redirs = "") {
  return sh("'" + g_secreto + "' " + args + " " + redirs);
}
static int keygen(const std::string& args, const std::string& redirs = "") {
  return sh("'" + g_keygen + "' " + args + " " + redirs);
}

static void write_file(const fs::path& p, const std::string& data) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
}

static std::string read_trim(const fs::path& p) {
  std::string s = slurp(p.string());
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}


static void test_keygen() {
  CHECK(keygen("-o " + q(P("id.txt")), "2> " + q(P("id.pub.err"))) == 0);
  struct stat st;
  CHECK(::stat(P("id.txt").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
  std::string secret = read_trim(P("id.txt"));
  CHECK(secret.rfind("SECRETO-SECRET-KEY-1", 0) == 0);
  std::string recipient = read_trim(P("id.pub.err"));
  CHECK(recipient.rfind("secreto1", 0) == 0);

  // -y derives the same recipient, from a file and from stdin.
  CHECK(keygen("-y " + q(P("id.txt")), "> " + q(P("recipient.txt"))) == 0);
  CHECK(read_trim(P("recipient.txt")) == recipient);
  CHECK(keygen("-y", "< " + q(P("id.txt")) + " > " + q(P("recipient2.txt"))) == 0);
  CHECK(read_trim(P("recipient2.txt")) == recipient);

  // stdout mode.
  CHECK(keygen("", "> " + q(P("id2.txt")) + " 2>/dev/null") == 0);
  CHECK(read_trim(P("id2.txt")).rfind("SECRETO-SECRET-KEY-1", 0) == 0);

  // Signing keys.
  CHECK(keygen("--signing -o " + q(P("sig.key")), "2> " + q(P("sig.pub.err"))) == 0);
  CHECK(::stat(P("sig.key").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
  std::string signer = read_trim(P("sig.pub.err"));
  CHECK(signer.rfind("secretosig1", 0) == 0);
  CHECK(keygen("--signing -y " + q(P("sig.key")), "> " + q(P("signer.txt"))) == 0);
  CHECK(read_trim(P("signer.txt")) == signer);
  // A signing key is not an identity and vice versa.
  CHECK(keygen("-y " + q(P("sig.key")), "2>/dev/null >/dev/null") == 1);
  CHECK(keygen("--signing -y " + q(P("id.txt")), "2>/dev/null >/dev/null") == 1);

  // Usage errors / I/O errors.
  CHECK(keygen("-y -o x", "2>/dev/null") == 1);
  CHECK(keygen("--bogus", "2>/dev/null") == 1);
  CHECK(keygen("stray-arg", "2>/dev/null") == 1);
  CHECK(keygen("-y " + q(P("does-not-exist")), "2>/dev/null") == 2);
  CHECK(keygen("-o " + q(P("no-such-dir/key")), "2>/dev/null") == 2);
}

static std::string make_plain(std::size_t n) {
  std::string s(n, '\0');
  for (std::size_t i = 0; i < n; ++i) s[i] = static_cast<char>((i * 131 + 17) & 0xff);
  return s;
}

static void test_encrypt_decrypt() {
  std::string recipient = read_trim(P("recipient.txt"));
  std::string plain = make_plain(150000);
  write_file(P("plain.bin"), plain);

  // -r with file input / file output, -d with -i.
  CHECK(run("-e -r " + recipient + " -o " + q(P("c1.sec")) + " " + q(P("plain.bin"))) == 0);
  CHECK(slurp(P("c1.sec").string()).rfind("secreto/v1\n-> mlkem1024p384 ", 0) == 0);
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("p1.out")) + " " + q(P("c1.sec"))) == 0);
  CHECK(slurp(P("p1.out").string()) == plain);
  struct stat st;
  CHECK(::stat(P("p1.out").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);

  // Implied -e; stdin/stdout; -R recipients file with comments.
  write_file(P("recips.txt"), "# my recipients\n\n" + recipient + "\n");
  CHECK(run("-R " + q(P("recips.txt")), "< " + q(P("plain.bin")) + " > " + q(P("c2.sec"))) == 0);
  CHECK(run("-d -i " + q(P("id.txt")), "< " + q(P("c2.sec")) + " > " + q(P("p2.out"))) == 0);
  CHECK(slurp(P("p2.out").string()) == plain);
  // "-" means stdin / stdout.
  CHECK(run("-d -i " + q(P("id.txt")) + " -o - -", "< " + q(P("c2.sec")) + " > " + q(P("p2b.out"))) ==
        0);
  CHECK(slurp(P("p2b.out").string()) == plain);

  // Armor + padding.
  CHECK(run("-e -a --pad -r " + recipient + " -o " + q(P("c3.asc")) + " " + q(P("plain.bin"))) == 0);
  CHECK(slurp(P("c3.asc").string()).rfind("-----BEGIN SECRETO ENCRYPTED FILE-----\n", 0) == 0);
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("p3.out")) + " " + q(P("c3.asc"))) == 0);
  CHECK(slurp(P("p3.out").string()) == plain);

  // Multiple recipients: the second identity can decrypt too.
  CHECK(keygen("-o " + q(P("idb.txt")), "2> " + q(P("idb.err"))) == 0);
  std::string recipient_b = read_trim(P("idb.err"));
  CHECK(run("-e -r " + recipient + " -r " + recipient_b + " -o " + q(P("c4.sec")) + " " +
            q(P("plain.bin"))) == 0);
  CHECK(run("-d -i " + q(P("idb.txt")) + " -o " + q(P("p4.out")) + " " + q(P("c4.sec"))) == 0);
  CHECK(slurp(P("p4.out").string()) == plain);
  // Identity file with several identities.
  write_file(P("ids.txt"), "# two\n" + read_trim(P("id2.txt")) + "\n" + read_trim(P("idb.txt")) + "\n");
  CHECK(::chmod(P("ids.txt").c_str(), 0600) == 0);
  CHECK(run("-d -i " + q(P("ids.txt")) + " -o " + q(P("p4b.out")) + " " + q(P("c4.sec"))) == 0);
  CHECK(slurp(P("p4b.out").string()) == plain);

  // Empty input.
  write_file(P("empty.bin"), "");
  CHECK(run("-e -r " + recipient + " -o " + q(P("c5.sec")) + " " + q(P("empty.bin"))) == 0);
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("p5.out")) + " " + q(P("c5.sec"))) == 0);
  CHECK(slurp(P("p5.out").string()).empty());

  // Exit code 3: wrong identity. Exit code 4: corruption.
  CHECK(run("-d -i " + q(P("id2.txt")) + " -o " + q(P("p6.out")) + " " + q(P("c1.sec")),
            "2>/dev/null") == 3);
  CHECK(!fs::exists(P("p6.out")));
  std::string ct = slurp(P("c1.sec").string());
  std::string bad = ct;
  bad[bad.size() - 3] ^= 1;
  write_file(P("bad1.sec"), bad);
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("p7.out")) + " " + q(P("bad1.sec")),
            "2>/dev/null") == 4);
  CHECK(!fs::exists(P("p7.out")));
  write_file(P("bad2.sec"), ct.substr(0, ct.size() - 20));
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("p8.out")) + " " + q(P("bad2.sec")),
            "2>/dev/null") == 4);
  write_file(P("bad3.sec"), "not a secreto file\n");
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("p9.out")) + " " + q(P("bad3.sec")),
            "2>/dev/null") == 4);
  CHECK(run("-d -i " + q(P("id.txt")), "< /dev/null >/dev/null 2>&1") == 4);

  // An existing destination is replaced atomically; no temp files remain.
  write_file(P("existing.out"), "old");
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("existing.out")) + " " + q(P("c1.sec"))) == 0);
  CHECK(slurp(P("existing.out").string()) == plain);
  for (const auto& e : fs::directory_iterator(g_dir))
    CHECK_MSG(e.path().filename().string().rfind(".secreto-tmp-", 0) != 0, "stale temp file");
  // A failed decrypt must not clobber an existing destination.
  write_file(P("keep.out"), "keep me");
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("keep.out")) + " " + q(P("bad1.sec")),
            "2>/dev/null") == 4);
  CHECK(slurp(P("keep.out").string()) == "keep me");
}

static void test_signing() {
  std::string recipient = read_trim(P("recipient.txt"));
  std::string signer = read_trim(P("signer.txt"));
  std::string plain = make_plain(3000);
  write_file(P("splain.bin"), plain);

  CHECK(run("-e --pad --sign " + q(P("sig.key")) + " -r " + recipient + " -o " + q(P("s1.sec")) +
            " " + q(P("splain.bin"))) == 0);
  CHECK(run("-d -i " + q(P("id.txt")) + " --verify " + signer + " -o " + q(P("s1.out")) + " " +
            q(P("s1.sec"))) == 0);
  CHECK(slurp(P("s1.out").string()) == plain);

  // Verify key from a file.
  CHECK(run("-d -i " + q(P("id.txt")) + " --verify " + q(P("signer.txt")) + " -o " +
            q(P("s1b.out")) + " " + q(P("s1.sec"))) == 0);

  // Without --verify: released, with a warning naming the signer.
  CHECK(run("-d -i " + q(P("id.txt")) + " -o " + q(P("s2.out")) + " " + q(P("s1.sec")),
            "2> " + q(P("s2.err"))) == 0);
  CHECK(slurp(P("s2.out").string()) == plain);
  CHECK(slurp(P("s2.err").string()).find("signed by signer") != std::string::npos);

  // Wrong signer -> 5 and nothing released.
  CHECK(keygen("--signing", "> " + q(P("sig2.key")) + " 2> " + q(P("sig2.err"))) == 0);
  std::string other = read_trim(P("sig2.err"));
  CHECK(run("-d -i " + q(P("id.txt")) + " --verify " + other + " -o " + q(P("s3.out")) + " " +
            q(P("s1.sec")), "2>/dev/null") == 5);
  CHECK(!fs::exists(P("s3.out")));
  // stdout with a failed verification prints nothing.
  CHECK(run("-d -i " + q(P("id.txt")) + " --verify " + other + " " + q(P("s1.sec")),
            "2>/dev/null > " + q(P("s4.out"))) == 5);
  CHECK(slurp(P("s4.out").string()).empty());

  // --verify on an unsigned file -> 5.
  CHECK(run("-d -i " + q(P("id.txt")) + " --verify " + signer + " -o " + q(P("s5.out")) + " " +
            q(P("c1.sec")), "2>/dev/null") == 5);
  // Malformed verify key -> 1.
  CHECK(run("-d -i " + q(P("id.txt")) + " --verify secretosig1qqqq -o " + q(P("s6.out")) + " " +
            q(P("s1.sec")), "2>/dev/null") == 1);
  // Bad signing key file -> 1; missing -> 2.
  CHECK(run("-e --sign " + q(P("id.txt")) + " -r " + recipient + " " + q(P("splain.bin")),
            "2>/dev/null >/dev/null") == 1);
  CHECK(run("-e --sign " + q(P("missing.key")) + " -r " + recipient + " " + q(P("splain.bin")),
            "2>/dev/null >/dev/null") == 2);
}

static void test_usage_and_io_errors() {
  std::string recipient = read_trim(P("recipient.txt"));
  const std::string quiet = "2>/dev/null >/dev/null </dev/null";
  CHECK(run("", quiet) == 1);                                  // nothing to do
  CHECK(run("-e", quiet) == 1);                                // no recipients
  CHECK(run("-d", quiet) == 1);                                // no identity
  CHECK(run("-e -d -r " + recipient, quiet) == 1);             // both modes
  CHECK(run("-e -p -r " + recipient, quiet) == 1);             // -p with -r
  CHECK(run("-r not-a-recipient", quiet) == 1);                // invalid recipient
  CHECK(run("-e -r " + recipient + " -i " + q(P("id.txt")), quiet) == 1);
  CHECK(run("-d -i " + q(P("id.txt")) + " -r " + recipient, quiet) == 1);
  CHECK(run("-d -i " + q(P("id.txt")) + " -a", quiet) == 1);
  CHECK(run("-d -i " + q(P("id.txt")) + " --pad", quiet) == 1);
  CHECK(run("--no-such-flag", quiet) == 1);
  CHECK(run("-e -r " + recipient + " a b", quiet) == 1);       // two inputs
  CHECK(run("-R " + q(P("id.txt")), quiet) == 1);              // identity in a recipient file
  CHECK(run("-d -i " + q(P("recipient.txt")), quiet) == 1);    // recipient in an identity file
  write_file(P("empty-keys.txt"), "# nothing here\n");
  CHECK(run("-d -i " + q(P("empty-keys.txt")), quiet) == 1);
  CHECK(run("-R " + q(P("empty-keys.txt")), quiet) == 1);

  // I/O errors -> 2.
  CHECK(run("-d -i " + q(P("missing.txt")), quiet) == 2);
  CHECK(run("-R " + q(P("missing.txt")), quiet) == 2);
  CHECK(run("-e -r " + recipient + " " + q(P("missing.bin")), quiet) == 2);
  CHECK(run("-e -r " + recipient + " -o " + q(P("no-such-dir/out")) + " " + q(P("plain.bin")),
            quiet) == 2);

  // Passphrase FD handling (no argv passphrases exist).
  CHECK(sh("SECRETO_PASSPHRASE_FD=abc '" + g_secreto + "' -d -p " + quiet) == 1);
  CHECK(sh("SECRETO_PASSPHRASE_FD=77 '" + g_secreto + "' -d -p " + quiet) == 1);
  CHECK(sh("SECRETO_PASSPHRASE_FD=3 '" + g_secreto + "' -d -p " + q(P("c1.sec")) +
           " 2>/dev/null 3< /dev/null") == 3);  // empty passphrase never matches an mlkem file

  // Group-readable identity file triggers a warning but still works.
  CHECK(::chmod(P("id2.txt").c_str(), 0644) == 0);
  CHECK(run("-d -i " + q(P("id2.txt")) + " -o " + q(P("w.out")) + " " + q(P("c1.sec")),
            "2> " + q(P("w.err"))) == 3);
  CHECK(slurp(P("w.err").string()).find("warning") != std::string::npos);
}

// Full-strength passphrase encryption (1 GiB Argon2id); opt-in because of memory use.
static void test_passphrase_full() {
  if (std::getenv("SECRETO_TEST_FULL_ARGON") == nullptr) return;
  std::string plain = make_plain(1000);
  write_file(P("pp.bin"), plain);
  write_file(P("pass.txt"), "correct horse\r\n");
  CHECK(sh("SECRETO_PASSPHRASE_FD=3 '" + g_secreto + "' -e -p -o " + q(P("pp.sec")) + " " +
           q(P("pp.bin")) + " 3< " + q(P("pass.txt"))) == 0);
  std::string c = slurp(P("pp.sec").string());
  CHECK(c.find("-> argon2id ") != std::string::npos && c.find(" 1048576 3 4\n") != std::string::npos);
  CHECK(sh("SECRETO_PASSPHRASE_FD=3 '" + g_secreto + "' -d -p -o " + q(P("pp.out")) + " " +
           q(P("pp.sec")) + " 3< " + q(P("pass.txt"))) == 0);
  CHECK(slurp(P("pp.out").string()) == plain);
}

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: test_cli PATH-TO-secreto PATH-TO-secreto-keygen\n");
    return 2;
  }
  g_secreto = fs::absolute(argv[1]).string();
  g_keygen = fs::absolute(argv[2]).string();

  std::string tmpl = (fs::current_path() / "cli-tmp-XXXXXX").string();
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  if (::mkdtemp(buf.data()) == nullptr) {
    std::fprintf(stderr, "cannot create temp dir\n");
    return 2;
  }
  g_dir = buf.data();

  try {
    test_keygen();
    test_encrypt_decrypt();
    test_signing();
    test_usage_and_io_errors();
    test_passphrase_full();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "exception: %s\n", e.what());
    fs::remove_all(g_dir);
    return 1;
  }
  fs::remove_all(g_dir);
  return finish("test_cli");
}
