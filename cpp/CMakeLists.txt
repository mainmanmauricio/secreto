cmake_minimum_required(VERSION 3.20)
project(secreto-cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SECRETO_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

find_package(OpenSSL 3.5 REQUIRED)
find_package(Threads REQUIRED)

set(SECRETO_WARNINGS -Wall -Wextra -Werror)
set(SECRETO_SAN_FLAGS "")
if(SECRETO_SANITIZE)
  set(SECRETO_SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=undefined
                        -fno-omit-frame-pointer)
endif()

add_library(libsecreto STATIC
  src/armor.cpp
  src/base64.cpp
  src/bech32.cpp
  src/cli_keygen.cpp
  src/cli_secreto.cpp
  src/common.cpp
  src/crypto.cpp
  src/format.cpp
  src/header.cpp
  src/hpke.cpp
  src/io.cpp
  src/kem.cpp
  src/keys.cpp
  src/padme.cpp
  src/sign.cpp
  src/stream.cpp
)
set_target_properties(libsecreto PROPERTIES OUTPUT_NAME secreto)
target_include_directories(libsecreto PUBLIC include)
target_compile_options(libsecreto PRIVATE ${SECRETO_WARNINGS} ${SECRETO_SAN_FLAGS})
target_link_libraries(libsecreto PUBLIC OpenSSL::Crypto Threads::Threads)
if(SECRETO_SANITIZE)
  target_link_options(libsecreto PUBLIC ${SECRETO_SAN_FLAGS})
endif()

add_executable(secreto apps/secreto.cpp)
target_compile_options(secreto PRIVATE ${SECRETO_WARNINGS} ${SECRETO_SAN_FLAGS})
target_link_libraries(secreto PRIVATE libsecreto)

add_executable(secreto-keygen apps/secreto-keygen.cpp)
target_compile_options(secreto-keygen PRIVATE ${SECRETO_WARNINGS} ${SECRETO_SAN_FLAGS})
target_link_libraries(secreto-keygen PRIVATE libsecreto)

# ---------------------------------------------------------------- tests ----
enable_testing()

set(SECRETO_VECTORS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../vectors" CACHE PATH
    "Directory containing components/ and testkit/ vectors")

function(secreto_add_test name)
  add_executable(${name} tests/${name}.cpp)
  target_compile_options(${name} PRIVATE ${SECRETO_WARNINGS} ${SECRETO_SAN_FLAGS})
  target_include_directories(${name} PRIVATE tests)
  target_link_libraries(${name} PRIVATE libsecreto)
  target_compile_definitions(${name} PRIVATE
    SECRETO_VECTORS_DIR="${SECRETO_VECTORS_DIR}")
endfunction()

secreto_add_test(test_components)
secreto_add_test(test_unit)
secreto_add_test(test_vectors)
secreto_add_test(test_cli)

add_test(NAME components COMMAND test_components)
add_test(NAME unit COMMAND test_unit)
add_test(NAME testkit_library COMMAND test_vectors)
add_test(NAME testkit_cli COMMAND test_vectors --cli $<TARGET_FILE:secreto>)
add_test(NAME cli_integration
         COMMAND test_cli $<TARGET_FILE:secreto> $<TARGET_FILE:secreto-keygen>)
