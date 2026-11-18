cmake_minimum_required(VERSION 3.19)
project(traceq_capture C)
# The generated empty translation unit is only a shared-library link container.
# All self-owned runtime code is built by Cargo; Gum remains the pinned C archive.
get_filename_component(TRACEQ_RUST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
option(TRACEQ_GUM_ONLY "Build the patched native Gum archive for the host lab" OFF)
if(TRACEQ_GUM_ONLY)
    include(cmake/TraceqGum.cmake)
    return()
endif()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/rust-link.c" "/* Rust static library link container. */\n")
add_library(traceq_capture SHARED "${CMAKE_CURRENT_BINARY_DIR}/rust-link.c")
if(NOT ANDROID)
    message(FATAL_ERROR "Use make capture-host from the full checkout for the macOS native lab")
endif()
if(NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "The pinned capture ABI supports Android ARM64")
endif()
include(cmake/TraceqGum.cmake)
set(_traceq_rust_target aarch64-linux-android)
set(_traceq_target_env "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=${CMAKE_C_COMPILER}")
target_link_libraries(traceq_capture PRIVATE log dl m z)
target_link_options(traceq_capture PRIVATE "-Wl,--exclude-libs,libtraceq-gum.a" "-Wl,--gc-sections")
set(_traceq_rust_library "${TRACEQ_RUST_ROOT}/.deps/rust/target/${_traceq_rust_target}/release/libtraceq_capture.a")
file(GLOB_RECURSE _traceq_rust_sources CONFIGURE_DEPENDS
    "${TRACEQ_RUST_ROOT}/rust/traceq-capture/src/*.rs"
    "${TRACEQ_RUST_ROOT}/rust/traceq-core/src/*.rs"
    "${TRACEQ_RUST_ROOT}/rust/traceq-observer/src/*.rs")
add_custom_command(OUTPUT "${_traceq_rust_library}"
    COMMAND "${CMAKE_COMMAND}" -E env ${_traceq_target_env}
        "${Python3_EXECUTABLE}" "${TRACEQ_RUST_ROOT}/tools/rust_workspace.py"
        build --locked --release -p traceq-capture --target "${_traceq_rust_target}"
    DEPENDS ${_traceq_rust_sources}
        "${TRACEQ_RUST_ROOT}/rust/traceq-capture/Cargo.toml"
        "${TRACEQ_RUST_ROOT}/rust/traceq-core/Cargo.toml"
        "${TRACEQ_RUST_ROOT}/rust/traceq-observer/Cargo.toml"
        "${TRACEQ_RUST_ROOT}/rust/Cargo.toml" "${TRACEQ_RUST_ROOT}/rust/Cargo.lock"
        "${TRACEQ_RUST_ROOT}/tools/rust_workspace.py"
    WORKING_DIRECTORY "${TRACEQ_RUST_ROOT}"
    COMMENT "Building the Rust capture SDK with the pinned Gum ABI" VERBATIM)
add_custom_target(traceq_rust_capture DEPENDS "${_traceq_rust_library}")
add_dependencies(traceq_capture traceq_rust_capture)
# Explicit undefined roots retain only public SDK functions; Rust std and Gum
# symbols remain hidden on Android through the version script.
# A version script exports exactly the stable capture ABI from the archive.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/capture-exports.map"
    "{ global: traceq_capture_invoke; traceq_capture_invoke_at; traceq_capture_invoke_ranges_at; local: *; };\n")
target_link_options(traceq_capture PRIVATE
    "-Wl,-u,traceq_capture_invoke" "-Wl,-u,traceq_capture_invoke_at" "-Wl,-u,traceq_capture_invoke_ranges_at"
    "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/capture-exports.map")
# --exclude-libs must not localize SDK roots themselves; the version script
# hides all other Rust internals, and embedded Gum is separately localized.
target_link_libraries(traceq_capture PRIVATE "${_traceq_rust_library}" "${TRACEQ_GUM_ARCHIVE}")
