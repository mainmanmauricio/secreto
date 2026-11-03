// Entry points of the two command-line programs.
#pragma once

namespace secreto::cli {

// `secreto` (spec/cli.md). Returns the process exit code.
int secreto_main(int argc, char** argv);

// `secreto-keygen` (spec/cli.md). Returns the process exit code.
int keygen_main(int argc, char** argv);

}  // namespace secreto::cli
