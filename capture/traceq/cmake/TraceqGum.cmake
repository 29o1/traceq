# Build the source-available ARM64 backend against the same official devkit.
# The downloaded archive stays immutable; only the Stalker member is replaced.
file(READ "${TRACEQ_RUST_ROOT}/dependencies/gum-devkits.json" _traceq_gum_spec)
string(JSON _traceq_gum_version GET "${_traceq_gum_spec}" version)
if(ANDROID)
    set(_traceq_gum_platform android-arm64)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(_traceq_gum_platform macos-arm64)
else()
    message(FATAL_ERROR "The source-backed Gum build is qualified for Android/macOS ARM64")
endif()
if(NOT TRACEQ_GUM_DEVKIT_DIR)
    set(TRACEQ_GUM_DEVKIT_DIR "${TRACEQ_RUST_ROOT}/.deps/frida-gum-${_traceq_gum_version}-${_traceq_gum_platform}")
endif()
set(_traceq_gum_input "${TRACEQ_GUM_DEVKIT_DIR}/libfrida-gum.a")
set(_traceq_gum_header "${TRACEQ_GUM_DEVKIT_DIR}/frida-gum.h")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_traceq_gum_input}" "${_traceq_gum_header}"
    "${TRACEQ_RUST_ROOT}/dependencies/gum-devkits.json")
foreach(_member libfrida-gum.a frida-gum.h)
    string(JSON _expected GET "${_traceq_gum_spec}" platforms ${_traceq_gum_platform} members ${_member})
    file(SHA256 "${TRACEQ_GUM_DEVKIT_DIR}/${_member}" _actual)
    if(NOT _actual STREQUAL _expected)
        message(FATAL_ERROR "Gum ${_traceq_gum_version} ${_member} identity mismatch; run tools/dependencies.py gum --platform ${_traceq_gum_platform}")
    endif()
endforeach()
add_library(traceq_gum_backend OBJECT vendor/frida-gum-arm64/gumstalker-arm64.c)
set_target_properties(traceq_gum_backend PROPERTIES
    POSITION_INDEPENDENT_CODE ON C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_include_directories(traceq_gum_backend PRIVATE "${TRACEQ_GUM_DEVKIT_DIR}")
target_compile_definitions(traceq_gum_backend PRIVATE GUM_STATIC G_DISABLE_ASSERT G_DISABLE_CHECKS)
if(ANDROID)
    target_compile_definitions(traceq_gum_backend PRIVATE HAVE_LINUX HAVE_ANDROID)
else()
    target_compile_definitions(traceq_gum_backend PRIVATE HAVE_DARWIN HAVE_MACOS)
endif()
target_compile_options(traceq_gum_backend PRIVATE -Os -ffunction-sections -fdata-sections)
set(_traceq_gum_dir "${CMAKE_CURRENT_BINARY_DIR}/gum")
string(JSON _traceq_gum_backend_member GET "${_traceq_gum_spec}" backend_member)
set(_traceq_gum_member "${_traceq_gum_dir}/${_traceq_gum_backend_member}")
set(TRACEQ_GUM_ARCHIVE "${_traceq_gum_dir}/libtraceq-gum.a")
add_custom_command(OUTPUT "${TRACEQ_GUM_ARCHIVE}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${_traceq_gum_dir}"
    COMMAND "${CMAKE_COMMAND}" -E copy "${_traceq_gum_input}" "${TRACEQ_GUM_ARCHIVE}"
    COMMAND "${CMAKE_COMMAND}" -E copy $<TARGET_OBJECTS:traceq_gum_backend> "${_traceq_gum_member}"
    COMMAND "${CMAKE_AR}" r "${TRACEQ_GUM_ARCHIVE}" "${_traceq_gum_member}"
    DEPENDS "${_traceq_gum_input}" traceq_gum_backend $<TARGET_OBJECTS:traceq_gum_backend>
    COMMENT "Building Gum ${_traceq_gum_version} with traceq FP context preservation"
    VERBATIM)
add_custom_target(traceq_gum_archive ALL DEPENDS "${TRACEQ_GUM_ARCHIVE}")
if(TARGET traceq_capture)
    add_dependencies(traceq_capture traceq_gum_archive)
endif()
