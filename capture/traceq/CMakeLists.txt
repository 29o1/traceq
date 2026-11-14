cmake_minimum_required(VERSION 3.13)
project(traceq_capture CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/libs)
include_directories(${CMAKE_SOURCE_DIR})

set(TRACEQ_SOURCES
        src/main.cpp
        src/TraceqCapture.cpp
        src/Utils.cpp
        src/CallbackContext.cpp
        src/FuncPrinter.cpp
)

add_library(traceq_capture SHARED
        ${TRACEQ_SOURCES}
)

option(TRACEQ_WRITE_STREAM "Build experimental scoped write-evidence collector" OFF)
option(TRACEQ_CAPTURE_PERF "Build experimental capture cost probes and counters" OFF)
set(TRACEQ_INCLUDE_DIR "" CACHE PATH "traceq cli/include directory for the experimental stream contract")
if(NOT TRACEQ_INCLUDE_DIR AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../cli/include/traceq/write_stream.h")
    set(TRACEQ_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../cli/include")
endif()
if(TRACEQ_WRITE_STREAM)
    if(NOT EXISTS "${TRACEQ_INCLUDE_DIR}/traceq/write_stream.h")
        message(FATAL_ERROR "Set TRACEQ_INCLUDE_DIR to traceq/cli/include")
    endif()
    target_sources(traceq_capture PRIVATE src/WriteStream.cpp)
    target_compile_definitions(traceq_capture PRIVATE TRACEQ_WRITE_STREAM)
    if(TRACEQ_CAPTURE_PERF)
        target_compile_definitions(traceq_capture PRIVATE TRACEQ_CAPTURE_PERF)
    endif()
    target_compile_features(traceq_capture PRIVATE cxx_std_17)
    target_include_directories(traceq_capture PRIVATE "${TRACEQ_INCLUDE_DIR}")
endif()

if(ANDROID)
    message(STATUS "Configuring for Android")

    set(ANDROID_SYSROOT_INCLUDE "${CMAKE_SYSROOT}/usr/include")

    target_include_directories(traceq_capture SYSTEM PUBLIC .
            ${ANDROID_SYSROOT_INCLUDE})

    target_link_libraries(traceq_capture PRIVATE ${CMAKE_SOURCE_DIR}/libs/FridaGum-Android-17.8.3-fix.a)
    target_link_libraries(traceq_capture PRIVATE log dl m z)
    if(TRACEQ_WRITE_STREAM)
        target_sources(traceq_capture PRIVATE src/AndroidCapture.cpp)
        # Keep the embedded Gum/GLib distinct from the injecting agent's copy.
        target_link_options(traceq_capture PRIVATE "-Wl,--exclude-libs,ALL")
    endif()

else()
    message(STATUS "Configuring for iOS")

    enable_language(OBJCXX)

    execute_process(
            COMMAND xcode-select -p
            OUTPUT_VARIABLE DEVELOPER_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT DEVELOPER_DIR)
        message(FATAL_ERROR "Unable to locate Xcode developer directory")
    endif()

    set(CMAKE_XCODE_DEVELOPER_DIR ${DEVELOPER_DIR})

    execute_process(
            COMMAND /usr/bin/env DEVELOPER_DIR=${DEVELOPER_DIR} xcrun --sdk iphoneos --show-sdk-path
            OUTPUT_VARIABLE IOS_SDK_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    set(CMAKE_OSX_SYSROOT ${IOS_SDK_PATH})
    message(STATUS "iOS SDK Path: ${IOS_SDK_PATH}")

    set_source_files_properties(${TRACEQ_SOURCES} PROPERTIES LANGUAGE OBJCXX)

    target_include_directories(traceq_capture SYSTEM PUBLIC .)

    set_target_properties(traceq_capture PROPERTIES
            LINKER_LANGUAGE OBJCXX
            OBJCXX_STANDARD 11
            OBJCXX_STANDARD_REQUIRED YES
            BUNDLE FALSE
            FRAMEWORK FALSE
            XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
            XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
            XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER ""
            MACOSX_BUNDLE FALSE
    )

    target_compile_options(traceq_capture PRIVATE
            -isysroot ${IOS_SDK_PATH}
            -arch arm64
            -miphoneos-version-min=12.0
            -fvisibility=hidden
            -Wno-unused-command-line-argument
    )

    target_link_options(traceq_capture PRIVATE
            -isysroot ${IOS_SDK_PATH}
            -arch arm64
            -miphoneos-version-min=12.0
    )

    target_link_libraries(traceq_capture
            ${CMAKE_SOURCE_DIR}/libs/FridaGum-IOS-17.8.3-fix.a
            "-framework Foundation"
            "-framework CoreFoundation"
    )
endif()

if(TRACEQ_WRITE_STREAM)
    set_target_properties(traceq_capture PROPERTIES CXX_STANDARD 17 OBJCXX_STANDARD 17)
endif()
