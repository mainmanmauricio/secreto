// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include <getopt.h>

#include <cstdio>
#include <new>
#include <string>

#include "secreto/cli.hpp"
#include "secreto/io.hpp"
#include "secreto/kem.hpp"
#include "secreto/keys.hpp"
#include "secreto/sign.hpp"

namespace secreto::cli {

namespace {

void usage(std::FILE* f) {
  std::fputs(
      "usage:\n"
      "  secreto-keygen [-o OUT]\n"
      "  secreto-keygen -y [IN]\n"
      "  secreto-keygen --signing [-o OUT]\n"
      "  secreto-keygen --signing -y [IN]\n",
      f);
}

std::string text_of(const SecretBytes& b) {
  return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

int run(int argc, char** argv) {
  static const option longopts[] = {{"signing", no_argument, nullptr, 'S'},
                                    {"help", no_argument, nullptr, 'h'},
                                    {nullptr, 0, nullptr, 0}};
  bool signing = false, show_public = false, help = false, have_output = false;
  std::string output;
  optind = 1;
  opterr = 0;
  int c;
  while ((c = getopt_long(argc, argv, "o:yh", longopts, nullptr)) != -1) {
    switch (c) {
      case 'o': output = optarg; have_output = true; break;
      case 'y': show_public = true; break;
      case 'S': signing = true; break;
      case 'h': help = true; break;
      default: fail(kExitUsage, "unknown or incomplete option");
    }
  }
  if (help) {
    usage(stdout);
    return kExitOk;
  }
  if (argc - optind > 1) fail(kExitUsage, "too many arguments");
  const bool have_input = optind < argc;
  if (have_input && !show_public) fail(kExitUsage, "an input file is only valid with -y");
  if (show_public && have_output) fail(kExitUsage, "-o cannot be combined with -y");

  if (show_public) {
    std::string in = have_input ? argv[optind] : "-";
    if (in != "-") io::warn_if_permissive(in, signing ? "signing key" : "identity");
    SecretBytes text = io::read_input(in);
    std::string t = text_of(text);
    std::string out;
    if (signing) {
      SecretBytes sk = keys::parse_signing_key(t);
      out = keys::signer_public_to_bech32(sign::public_key(sk));
      out.push_back('\n');
    } else {
      for (const SecretBytes& seed : keys::parse_identities(t)) {
        out += keys::recipient_to_bech32(kem::encapsulation_key(seed));
        out.push_back('\n');
      }
    }
    cleanse(t.data(), t.size());
    io::write_output("-", as_bytes(out));
    return kExitOk;
  }

  std::string secret_line, public_line;
  if (signing) {
    SecretBytes sk = sign::generate_secret_key();
    secret_line = keys::signing_key_to_bech32(sk);
    public_line = keys::signer_public_to_bech32(sign::public_key(sk));
  } else {
    SecretBytes seed = kem::generate_seed();
    secret_line = keys::identity_to_bech32(seed);
    public_line = keys::recipient_to_bech32(kem::encapsulation_key(seed));
  }
  secret_line.push_back('\n');
  io::write_output(output, as_bytes(secret_line));
  cleanse(secret_line.data(), secret_line.size());
  // Match Rust/Python: bare Bech32 on stderr (no "Public key:" prefix).
  std::fprintf(stderr, "%s\n", public_line.c_str());
  return kExitOk;
}

}  // namespace

int keygen_main(int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const Error& e) {
    std::fprintf(stderr, "secreto-keygen: error: %s\n", e.what());
    return e.code();
  } catch (const std::bad_alloc&) {
    std::fputs("secreto-keygen: error: out of memory\n", stderr);
    return kExitIo;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "secreto-keygen: error: %s\n", e.what());
    return kExitIo;
  }
}

}  // namespace secreto::cli
