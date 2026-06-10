cmake_minimum_required(VERSION 3.20)
project(quantlib VERSION 4.0.0 LANGUAGES CXX)

option(QUANTLIB_BUILD_TESTS "Build tests" ON)
option(QUANTLIB_BUILD_BENCHES "Build benches" ON)
option(QUANTLIB_ENABLE_NATIVE "Enable native CPU tuning" ON)
option(QUANTLIB_ENABLE_OPENSSL "Enable OpenSSL backend for vetted classical primitives" ON)
option(QUANTLIB_ENABLE_LIBOQS "Enable liboqs-style post-quantum provider detection" ON)
option(QUANTLIB_BUILD_EXAMPLES "Build examples" ON)
option(QUANTLIB_BUILD_FUZZERS "Build fuzz harness entry points" OFF)
option(QUANTLIB_ENABLE_SANITIZERS "Enable Address/Undefined sanitizer flags on supported compilers" OFF)
option(QUANTLIB_ENABLE_COVERAGE "Enable coverage instrumentation on supported compilers" OFF)
option(QUANTLIB_ENABLE_PERF_GUARD "Enable performance-regression guard metadata" ON)
option(QUANTLIB_ENABLE_GPU "Enable optional GPU acceleration provider hooks" ON)
option(QUANTLIB_ENABLE_CUDA "Enable CUDA provider detection hooks" OFF)
option(QUANTLIB_ENABLE_OPENCL "Enable OpenCL provider detection hooks" ON)
option(QUANTLIB_ENABLE_CUDA_KERNELS "Enable compiled CUDA GPU crypto kernels when CUDA support is available" OFF)
option(QUANTLIB_ENABLE_OPENCL_KERNELS "Enable compiled OpenCL GPU crypto kernels when OpenCL support is available" ON)
option(QUANTLIB_ENABLE_HARDENING "Enable production hardening compile/link flags where supported" ON)
option(QUANTLIB_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(QUANTLIB_ENABLE_OPENSSL)
  find_package(OpenSSL QUIET)
endif()

if(QUANTLIB_ENABLE_CUDA)
  find_package(CUDAToolkit QUIET)
endif()

if(QUANTLIB_ENABLE_OPENCL)
  find_package(OpenCL QUIET)
endif()

if(QUANTLIB_ENABLE_LIBOQS)
  find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h)
  find_library(LIBOQS_LIBRARY NAMES oqs)
endif()

add_library(quantlib
  src/core/result.cpp
  src/core/bytes.cpp
  src/core/secure.cpp
  src/rng/rng.cpp
  src/hash/sha256.cpp
  src/hash/hash.cpp
  src/kdf/hkdf.cpp
  src/aead/aead.cpp
  src/classical/classical.cpp
  src/providers/registry.cpp
  src/security/policy.cpp
  src/protocol/transcript.cpp
  src/protocol/session.cpp
  src/protocol/replay.cpp
  src/protocol/record.cpp
  src/protocol/channel.cpp
  src/protocol/protocol.cpp
  src/security/audit.cpp
  src/runtime/selftest.cpp
  src/security/ssm.cpp
  src/security/vault.cpp
  src/runtime/release.cpp
  src/runtime/testing.cpp
  src/runtime/ops.cpp
  src/runtime/production.cpp
  src/facade/easy.cpp
  src/runtime/hardware.cpp
  src/runtime/batch.cpp
  src/runtime/throughput.cpp
  src/simd/cpu.cpp
  src/simd/simd.cpp
  src/simd/aligned.cpp
  src/gpu/gpu.cpp
  src/pq/pq.cpp
  src/pq/ml-kem.cpp
  src/pq/ml-dsa.cpp
  src/pq/slh-dsa.cpp
  src/hybrid/hybrid-kem.cpp
  src/hybrid/hybrid-sign.cpp
  src/key/key.cpp
  src/key/encoding.cpp
)

target_include_directories(quantlib PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_compile_features(quantlib PUBLIC cxx_std_20)
add_library(QuantLib::quantlib ALIAS quantlib)

if(OpenSSL_FOUND)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_OPENSSL=1)
  target_link_libraries(quantlib PUBLIC OpenSSL::Crypto)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_OPENSSL=0)
endif()


if(QUANTLIB_ENABLE_NATIVE)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_ENABLE_NATIVE=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_ENABLE_NATIVE=0)
endif()

if(QUANTLIB_ENABLE_GPU)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_ENABLE_GPU_BACKEND=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_ENABLE_GPU_BACKEND=0)
endif()

if(CUDAToolkit_FOUND)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_CUDA=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_CUDA=0)
endif()

if(CUDAToolkit_FOUND AND QUANTLIB_ENABLE_CUDA_KERNELS)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_CUDA_KERNELS=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_CUDA_KERNELS=0)
endif()

if(OpenCL_FOUND)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_OPENCL=1)
  target_link_libraries(quantlib PUBLIC OpenCL::OpenCL)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_OPENCL=0)
endif()

if(OpenCL_FOUND AND QUANTLIB_ENABLE_OPENCL_KERNELS)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_OPENCL_KERNELS=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_OPENCL_KERNELS=0)
endif()

if(LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_LIBOQS=1)
  target_include_directories(quantlib PRIVATE ${LIBOQS_INCLUDE_DIR})
  target_link_libraries(quantlib PUBLIC ${LIBOQS_LIBRARY})
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HAVE_LIBOQS=0)
endif()

if(MSVC)
  target_compile_options(quantlib PRIVATE /W4 /permissive-)
  if(QUANTLIB_WARNINGS_AS_ERRORS)
    target_compile_options(quantlib PRIVATE /WX)
  endif()
else()
  target_compile_options(quantlib PRIVATE -Wall -Wextra -Wpedantic)
  if(QUANTLIB_WARNINGS_AS_ERRORS)
    target_compile_options(quantlib PRIVATE -Werror)
  endif()
  if(QUANTLIB_ENABLE_NATIVE)
    target_compile_options(quantlib PRIVATE -O3)
  endif()
endif()


if(QUANTLIB_ENABLE_HARDENING)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HARDENED_BUILD=1)
  if(MSVC)
    target_compile_options(quantlib PRIVATE /sdl)
  else()
    target_compile_options(quantlib PRIVATE -fstack-protector-strong)
    if(CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo|MinSizeRel")
      target_compile_definitions(quantlib PUBLIC _FORTIFY_SOURCE=2)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      target_link_options(quantlib PRIVATE -Wl,-z,relro -Wl,-z,now)
    endif()
  endif()
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_HARDENED_BUILD=0)
endif()

if(QUANTLIB_WARNINGS_AS_ERRORS)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_WARNINGS_AS_ERRORS=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_WARNINGS_AS_ERRORS=0)
endif()

if(QUANTLIB_ENABLE_SANITIZERS)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_SANITIZERS_ENABLED=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_SANITIZERS_ENABLED=0)
endif()

if(QUANTLIB_ENABLE_COVERAGE)
  target_compile_definitions(quantlib PUBLIC QUANTLIB_COVERAGE_ENABLED=1)
else()
  target_compile_definitions(quantlib PUBLIC QUANTLIB_COVERAGE_ENABLED=0)
endif()

if(QUANTLIB_ENABLE_SANITIZERS AND NOT MSVC)
  target_compile_options(quantlib PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(quantlib PUBLIC -fsanitize=address,undefined)
endif()

if(QUANTLIB_ENABLE_COVERAGE AND NOT MSVC)
  target_compile_options(quantlib PUBLIC --coverage -O0 -g)
  target_link_options(quantlib PUBLIC --coverage)
endif()

add_executable(quantlib-keygen src/tools/keygen.cpp)
target_link_libraries(quantlib-keygen PRIVATE quantlib)

add_executable(quantlib-inspect src/tools/inspect.cpp)
target_link_libraries(quantlib-inspect PRIVATE quantlib)

add_executable(quantlib-ssm src/tools/ssm.cpp)
target_link_libraries(quantlib-ssm PRIVATE quantlib)

if(QUANTLIB_BUILD_TESTS)
  enable_testing()
  add_executable(quantlib-tests
    tests/test-core.cpp
    tests/test-hash.cpp
    tests/test-key.cpp
    tests/test-hybrid.cpp
    tests/test-classical.cpp
    tests/test-provider.cpp
    tests/test-kdf.cpp
    tests/test-pq.cpp
    tests/test-policy.cpp
    tests/test-transcript.cpp
    tests/test-session.cpp
    tests/test-replay.cpp
    tests/test-record.cpp
    tests/test-channel.cpp
    tests/test-protocol.cpp
    tests/test-audit.cpp
    tests/test-selftest.cpp
    tests/test-ssm.cpp
    tests/test-ssm-session.cpp
    tests/test-vault.cpp
    tests/test-release.cpp
    tests/test-testing.cpp
    tests/test-ops.cpp
    tests/test-production.cpp
    tests/test-easy.cpp
    tests/test-hardware.cpp
    tests/test-batch.cpp
    tests/test-throughput.cpp
    tests/test-simd.cpp
    tests/test-gpu.cpp
  )
  target_link_libraries(quantlib-tests PRIVATE quantlib)
  if(NOT MSVC)
    target_compile_options(quantlib-tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME quantlib-tests COMMAND quantlib-tests)
endif()

if(QUANTLIB_BUILD_EXAMPLES)
  add_executable(example-create-vault tests/examples/create-vault.cpp)
  target_link_libraries(example-create-vault PRIVATE quantlib)
  add_executable(example-sign-message tests/examples/sign-message.cpp)
  target_link_libraries(example-sign-message PRIVATE quantlib)
  add_executable(example-easy-wrapper tests/examples/easy-wrapper.cpp)
  target_link_libraries(example-easy-wrapper PRIVATE quantlib)
endif()

if(QUANTLIB_BUILD_BENCHES)
  add_executable(quantlib-bench tests/benchmarks/bench.cpp)
  target_link_libraries(quantlib-bench PRIVATE quantlib)
endif()

if(QUANTLIB_BUILD_FUZZERS)
  add_executable(quantlib-fuzz-record-decode tests/fuzz/record-decode.cpp)
  target_link_libraries(quantlib-fuzz-record-decode PRIVATE quantlib)
  add_executable(quantlib-fuzz-protocol-limits tests/fuzz/protocol-limits.cpp)
  target_link_libraries(quantlib-fuzz-protocol-limits PRIVATE quantlib)
endif()

install(TARGETS quantlib quantlib-keygen quantlib-inspect quantlib-ssm
  EXPORT QuantLibTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)
install(EXPORT QuantLibTargets FILE QuantLibTargets.cmake NAMESPACE QuantLib:: DESTINATION lib/cmake/QuantLib)

include(CMakePackageConfigHelpers)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/QuantLibConfig.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/QuantLibConfig.cmake INSTALL_DESTINATION lib/cmake/QuantLib)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/QuantLibConfigVersion.cmake VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/QuantLibConfig.cmake ${CMAKE_CURRENT_BINARY_DIR}/QuantLibConfigVersion.cmake DESTINATION lib/cmake/QuantLib)
