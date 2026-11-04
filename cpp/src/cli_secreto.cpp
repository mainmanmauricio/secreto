// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

#include "secreto/bech32.hpp"
#include "secreto/cli.hpp"
#include "secreto/format.hpp"
#include "secreto/io.hpp"
#include "secreto/keys.hpp"

namespace secreto::cli {

namespace {

constexpr std::size_t kMaxStdoutBuffer = 256ull << 20;

void usage(std::FILE* f) {
  std::fputs(
      "usage:\n"
      "  secreto [-e] (-r RECIPIENT | -R FILE)... [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]\n"
      "  secreto [-e] -p [--memory MIB] [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]\n"
      "  secreto -d (-i FILE)... | -p [--verify SIGNER_PUB] [-o OUT] [IN]\n"
      "\n"
      "The passphrase is read from SECRETO_PASSPHRASE_FD or /dev/tty.\n"
      "--memory sets Argon2id memory in MiB (default 64; range 64-4096; -p only).\n",
      f);
}

[[noreturn]] void usage_error(const std::string& msg) { fail(kExitUsage, msg); }

struct Options {
  bool encrypt = false;
  bool decrypt = false;
  bool passphrase = false;
  bool armor = false;
  bool pad = false;
  bool help = false;
  bool have_memory = false;
  std::uint32_t memory_mib = 64;
  std::vector<std::string> recipients;
  std::vector<std::string> recipient_files;
  std::vector<std::string> identity_files;
  std::string sign_file;
  std::string verify;
  std::string output;
  bool have_output = false;
  std::vector<std::string> inputs;
};

Options parse_args(int argc, char** argv) {
  static const option longopts[] = {{"pad", no_argument, nullptr, 'P'},
                                    {"sign", required_argument, nullptr, 'S'},
                                    {"verify", required_argument, nullptr, 'V'},
                                    {"memory", required_argument, nullptr, 'M'},
                                    {"help", no_argument, nullptr, 'h'},
                                    {nullptr, 0, nullptr, 0}};
  Options o;
  optind = 1;
  opterr = 0;
  int c;
  while ((c = getopt_long(argc, argv, "edr:R:i:pao:h", longopts, nullptr)) != -1) {
    switch (c) {
      case 'e': o.encrypt = true; break;
      case 'd': o.decrypt = true; break;
      case 'r': o.recipients.emplace_back(optarg); break;
      case 'R': o.recipient_files.emplace_back(optarg); break;
      case 'i': o.identity_files.emplace_back(optarg); break;
      case 'p': o.passphrase = true; break;
      case 'a': o.armor = true; break;
      case 'o': o.output = optarg; o.have_output = true; break;
      case 'P': o.pad = true; break;
      case 'M': {
        if (o.have_memory) usage_error("--memory given more than once");
        char* end = nullptr;
        unsigned long v = std::strtoul(optarg, &end, 10);
        if (end == optarg || *end != '\0' || v < 64 || v > 4096)
          usage_error("--memory must be an integer between 64 and 4096 (MiB)");
        o.memory_mib = static_cast<std::uint32_t>(v);
        o.have_memory = true;
        break;
      }
      case 'S':
        if (!o.sign_file.empty()) usage_error("--sign given more than once");
        o.sign_file = optarg;
        break;
      case 'V':
        if (!o.verify.empty()) usage_error("--verify given more than once");
        o.verify = optarg;
        break;
      case 'h': o.help = true; break;
      default:
        usage_error(optopt ? std::string("unknown or incomplete option -") +
                                 static_cast<char>(optopt)
                           : std::string("unknown or incomplete option ") + argv[optind - 1]);
    }
  }
  for (int i = optind; i < argc; ++i) o.inputs.emplace_back(argv[i]);
  if (o.inputs.size() > 1) usage_error("too many input files");
  return o;
}

std::string text_of(const SecretBytes& b) {
  return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

int run(int argc, char** argv) {
  Options o = parse_args(argc, argv);
  if (o.help) {
    usage(stdout);
    return kExitOk;
  }

  const bool have_recipients = !o.recipients.empty() || !o.recipient_files.empty();
  if (o.encrypt && o.decrypt) usage_error("-e and -d are mutually exclusive");
  bool do_decrypt = o.decrypt;
  if (!o.encrypt && !o.decrypt) {
    if (have_recipients || o.passphrase) {
      do_decrypt = false;
    } else {
      usage_error("specify -e or -d (see --help)");
    }
  }
  const std::string input = o.inputs.empty() ? "-" : o.inputs[0];

  if (!do_decrypt) {
    // ----------------------------------------------------------- encrypt
    if (!o.identity_files.empty() || !o.verify.empty())
      usage_error("-i and --verify are only valid when decrypting");
    if (!have_recipients && !o.passphrase) usage_error("encryption needs -r/-R or -p");
    if (o.passphrase && have_recipients) usage_error("-p cannot be combined with -r/-R");
    if (o.have_memory && !o.passphrase) usage_error("--memory requires -p");

    EncryptOptions eo;
    eo.pad = o.pad;
    eo.armor = o.armor;
    eo.argon.m_kib = o.memory_mib * 1024u;
    eo.argon.t = kArgonDefaultT;
    eo.argon.p = kArgonDefaultP;
    for (const std::string& r : o.recipients) eo.recipients.push_back(keys::recipient_from_bech32(r));
    for (const std::string& f : o.recipient_files) {
      SecretBytes text = io::read_file(f);
      for (Bytes& ek : keys::parse_recipients(text_of(text))) eo.recipients.push_back(std::move(ek));
    }
    if (!o.sign_file.empty()) {
      io::warn_if_permissive(o.sign_file, "signing key");
      SecretBytes text = io::read_file(o.sign_file);
      eo.signing_key = keys::parse_signing_key(text_of(text));
    }
    if (!o.have_output || o.output == "-") {
      if (!o.armor && io::stdout_is_tty())
        usage_error("refusing to write binary ciphertext to a terminal (use -a or -o)");
    }

    if (o.passphrase) {
      eo.passphrase = io::read_passphrase(true);
      if (eo.passphrase->empty()) usage_error("empty passphrase");
    }
    if (eo.armor) {
      // Armored output uses the in-memory path (Rust/Python stream PEM).
      SecretBytes content = io::read_input(input);
      Bytes out = encrypt(content, eo);
      io::write_output(o.output, out);
      return kExitOk;
    }

    std::FILE* in = nullptr;
    bool close_in = false;
    if (input.empty() || input == "-") {
      in = stdin;
    } else {
      in = std::fopen(input.c_str(), "rb");
      if (!in) fail(kExitIo, "cannot open " + input);
      close_in = true;
    }

    const bool to_stdout = !o.have_output || o.output == "-";
    try {
      if (to_stdout) {
        encrypt_to(in, stdout, eo);
      } else {
        std::string out_path = o.output;
        std::string dir = ".";
        auto slash = out_path.rfind('/');
        if (slash != std::string::npos) dir = out_path.substr(0, slash == 0 ? 1 : slash);
        std::string tmpl = dir + "/.secreto-out-XXXXXX";
        std::vector<char> tbuf(tmpl.begin(), tmpl.end());
        tbuf.push_back('\0');
        int tfd = ::mkstemp(tbuf.data());
        if (tfd < 0) fail(kExitIo, "cannot create temp output");
        ::fchmod(tfd, 0600);
        std::FILE* outf = ::fdopen(tfd, "wb");
        if (!outf) {
          ::close(tfd);
          ::unlink(tbuf.data());
          fail(kExitIo, "cannot open temp output");
        }
        try {
          encrypt_to(in, outf, eo);
          if (std::fflush(outf) != 0) fail(kExitIo, "flush failed");
          std::fclose(outf);
          outf = nullptr;
          if (::rename(tbuf.data(), out_path.c_str()) != 0) {
            ::unlink(tbuf.data());
            fail(kExitIo, "cannot rename output");
          }
        } catch (...) {
          if (outf) std::fclose(outf);
          ::unlink(tbuf.data());
          throw;
        }
      }
    } catch (...) {
      if (close_in) std::fclose(in);
      throw;
    }
    if (close_in) std::fclose(in);
    return kExitOk;
  }

  // ------------------------------------------------------------- decrypt
  if (!o.recipients.empty() || !o.recipient_files.empty() || o.pad || o.armor ||
      !o.sign_file.empty() || o.have_memory)
    usage_error("-r, -R, -a, --pad, --sign and --memory are only valid when encrypting");
  if (o.identity_files.empty() && !o.passphrase) usage_error("decryption needs -i or -p");

  DecryptOptions dopts;
  for (const std::string& f : o.identity_files) {
    io::warn_if_permissive(f, "identity");
    SecretBytes text = io::read_file(f);
    for (SecretBytes& id : keys::parse_identities(text_of(text)))
      dopts.identities.push_back(std::move(id));
  }
  if (!o.verify.empty()) {
    if (o.verify.rfind("secretosig1", 0) == 0) {
      dopts.verify_key = keys::signer_public_from_bech32(o.verify);
    } else {
      SecretBytes text = io::read_file(o.verify);
      auto lines = keys::key_lines(text_of(text));
      if (lines.size() != 1) usage_error("verify file must contain exactly one signer public key");
      dopts.verify_key = keys::signer_public_from_bech32(lines[0]);
    }
  }

  SecretBytes file = io::read_input(input);
  if (o.passphrase) dopts.passphrase = io::read_passphrase(false);

  DecryptResult r = decrypt(file, dopts);

  if (r.signed_file && !r.verified)
    std::fprintf(stderr,
                 "secreto: warning: file is signed by signer %s; signature NOT verified "
                 "(use --verify)\n",
                 hex_encode(r.signer_id).c_str());

  const bool to_stdout = !o.have_output || o.output == "-";
  if (to_stdout && !o.verify.empty() && r.content.size() > kMaxStdoutBuffer)
    usage_error("content too large to buffer for verification; use -o");
  io::write_output(o.output, r.content);
  return kExitOk;
}

}  // namespace

int secreto_main(int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const Error& e) {
    std::fprintf(stderr, "secreto: error: %s\n", e.what());
    if (e.code() == kExitUsage) std::fputs("try 'secreto --help' for usage\n", stderr);
    return e.code();
  } catch (const std::bad_alloc&) {
    std::fputs("secreto: error: out of memory\n", stderr);
    return kExitIo;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "secreto: error: %s\n", e.what());
    return kExitIo;
  }
}

}  // namespace secreto::cli
