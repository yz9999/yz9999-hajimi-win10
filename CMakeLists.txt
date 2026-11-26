cmake_minimum_required(VERSION 3.24)
cmake_policy(SET CMP0091 NEW)

project(HajimiNative
    VERSION 0.2.1
    DESCRIPTION "Hajimi Unified Cross-Platform (macOS + Windows) Native C11/C++17 Data-Plane, 15-Protocol Stack & Engine C-API"
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(HAJIMI_BUILD_TESTS "Build offline unit, v2 batch benchmark, and protocol interop test binaries" ON)
set(HAJIMI_TLS_BACKEND "AUTO" CACHE STRING "TLS & QUIC backend selection: AUTO (prefers cached OpenSSL or AWS-LC), AWSLC, or OPENSSL")
set_property(CACHE HAJIMI_TLS_BACKEND PROPERTY STRINGS AUTO AWSLC OPENSSL)

# Normalize target architecture label (x64 / arm64) to locate per-arch static vendor roots
if(NOT DEFINED HAJIMI_TARGET_ARCH)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64|arm64")
        set(HAJIMI_TARGET_ARCH "arm64")
    else()
        set(HAJIMI_TARGET_ARCH "x64")
    endif()
endif()

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/utf-8 /W3 /MP /EHsc)
    add_compile_definitions(
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        _WIN32_WINNT=0x0A00
        NTDDI_VERSION=0x0A00000B
    )
else()
    add_compile_options(-Wall -Wextra -Wno-deprecated-declarations)
endif()

# ============================================================================
# Locate Static Vendor Libraries (.build/Vendor/*): OpenSSL 3.5+ or AWS-LC
# ============================================================================
set(HAJIMI_VENDOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.build/Vendor")

function(hajimi_try_resolve_vendor OUT_VAR SUBDIR HEADER_REL)
    set(CANDIDATES
        "${HAJIMI_VENDOR_DIR}/${SUBDIR}/${HAJIMI_TARGET_ARCH}"
        "${HAJIMI_VENDOR_DIR}/${SUBDIR}"
    )
    foreach(CAND IN LISTS CANDIDATES)
        if(EXISTS "${CAND}/${HEADER_REL}")
            set(${OUT_VAR} "${CAND}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set(${OUT_VAR} "" PARENT_SCOPE)
endfunction()

function(hajimi_resolve_vendor_prefix OUT_VAR SUBDIR HEADER_REL)
    hajimi_try_resolve_vendor(FOUND_DIR "${SUBDIR}" "${HEADER_REL}")
    if(NOT FOUND_DIR STREQUAL "")
        set(${OUT_VAR} "${FOUND_DIR}" PARENT_SCOPE)
        return()
    endif()
    message(FATAL_ERROR "Missing vendor dependency '${SUBDIR}' (${HEADER_REL}). Run scripts/build_native_core.ps1 (Windows) or scripts/build_native_core.sh (macOS) first.")
endfunction()

set(HAJIMI_USE_AWSLC OFF)
set(HAJIMI_TLS_PREFIX "")

if(HAJIMI_TLS_BACKEND STREQUAL "AWSLC")
    if(DEFINED ENV{HAJIMI_AWSLC_ROOT} AND EXISTS "$ENV{HAJIMI_AWSLC_ROOT}/include/openssl/ssl.h")
        set(HAJIMI_TLS_PREFIX "$ENV{HAJIMI_AWSLC_ROOT}")
        set(HAJIMI_USE_AWSLC ON)
    else()
        hajimi_resolve_vendor_prefix(HAJIMI_TLS_PREFIX "AWSLC" "include/openssl/ssl.h")
        set(HAJIMI_USE_AWSLC ON)
    endif()
elseif(HAJIMI_TLS_BACKEND STREQUAL "OPENSSL")
    if(DEFINED ENV{HAJIMI_OPENSSL_ROOT} AND EXISTS "$ENV{HAJIMI_OPENSSL_ROOT}/include/openssl/ssl.h")
        set(HAJIMI_TLS_PREFIX "$ENV{HAJIMI_OPENSSL_ROOT}")
    else()
        hajimi_resolve_vendor_prefix(HAJIMI_TLS_PREFIX "OpenSSL" "include/openssl/ssl.h")
    endif()
else()
    # AUTO: check explicit env HAJIMI_TLS_BACKEND first, then prefer AWS-LC over OpenSSL
    if(DEFINED ENV{HAJIMI_TLS_BACKEND} AND "$ENV{HAJIMI_TLS_BACKEND}" STREQUAL "openssl")
        hajimi_try_resolve_vendor(CAND_OSSL_ENV "OpenSSL" "include/openssl/ssl.h")
        if(NOT CAND_OSSL_ENV STREQUAL "")
            set(HAJIMI_TLS_PREFIX "${CAND_OSSL_ENV}")
        elseif(DEFINED ENV{HAJIMI_OPENSSL_ROOT} AND EXISTS "$ENV{HAJIMI_OPENSSL_ROOT}/include/openssl/ssl.h")
            set(HAJIMI_TLS_PREFIX "$ENV{HAJIMI_OPENSSL_ROOT}")
        endif()
    endif()
    if(HAJIMI_TLS_PREFIX STREQUAL "")
        hajimi_try_resolve_vendor(CAND_AWSLC "AWSLC" "include/openssl/ssl.h")
        if(NOT CAND_AWSLC STREQUAL "")
            set(HAJIMI_TLS_PREFIX "${CAND_AWSLC}")
            set(HAJIMI_USE_AWSLC ON)
        elseif(DEFINED ENV{HAJIMI_AWSLC_ROOT} AND EXISTS "$ENV{HAJIMI_AWSLC_ROOT}/include/openssl/ssl.h")
            set(HAJIMI_TLS_PREFIX "$ENV{HAJIMI_AWSLC_ROOT}")
            set(HAJIMI_USE_AWSLC ON)
        else()
            hajimi_try_resolve_vendor(CAND_OSSL "OpenSSL" "include/openssl/ssl.h")
            if(NOT CAND_OSSL STREQUAL "")
                set(HAJIMI_TLS_PREFIX "${CAND_OSSL}")
            elseif(DEFINED ENV{HAJIMI_OPENSSL_ROOT} AND EXISTS "$ENV{HAJIMI_OPENSSL_ROOT}/include/openssl/ssl.h")
                set(HAJIMI_TLS_PREFIX "$ENV{HAJIMI_OPENSSL_ROOT}")
            else()
                message(FATAL_ERROR "Neither .build/Vendor/AWSLC nor .build/Vendor/OpenSSL was found. Run scripts/build_native_core first.")
            endif()
        endif()
    endif()
endif()

hajimi_resolve_vendor_prefix(HAJIMI_QUIC_PREFIX "HajimiQUIC" "include/ngtcp2/ngtcp2.h")
hajimi_resolve_vendor_prefix(HAJIMI_SSH_PREFIX "HajimiSSH" "include/libssh2.h")

find_library(HAJIMI_LIBCRYPTO NAMES crypto libcrypto PATHS "${HAJIMI_TLS_PREFIX}/lib" "${HAJIMI_TLS_PREFIX}/lib64" NO_DEFAULT_PATH REQUIRED)
find_library(HAJIMI_LIBSSL NAMES ssl libssl PATHS "${HAJIMI_TLS_PREFIX}/lib" "${HAJIMI_TLS_PREFIX}/lib64" NO_DEFAULT_PATH REQUIRED)
find_library(HAJIMI_LIBNGTCP2 NAMES ngtcp2 ngtcp2_static libngtcp2 PATHS "${HAJIMI_QUIC_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)

if(HAJIMI_USE_AWSLC)
    find_library(HAJIMI_LIBNGTCP2_CRYPTO
        NAMES ngtcp2_crypto_boringssl ngtcp2_crypto_boringssl_static libngtcp2_crypto_boringssl
        PATHS "${HAJIMI_QUIC_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)
else()
    find_library(HAJIMI_LIBNGTCP2_CRYPTO
        NAMES ngtcp2_crypto_ossl ngtcp2_crypto_ossl_static libngtcp2_crypto_ossl
        PATHS "${HAJIMI_QUIC_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)
endif()

find_library(HAJIMI_LIBNGHTTP3 NAMES nghttp3 nghttp3_static libnghttp3 PATHS "${HAJIMI_QUIC_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)
find_library(HAJIMI_LIBSSH2 NAMES libssh2 libssh2_static ssh2 PATHS "${HAJIMI_SSH_PREFIX}/lib" NO_DEFAULT_PATH REQUIRED)

message(STATUS "Hajimi Target Arch : ${HAJIMI_TARGET_ARCH}")
if(HAJIMI_USE_AWSLC)
    message(STATUS "Hajimi TLS Backend : AWS-LC (${HAJIMI_TLS_PREFIX})")
else()
    message(STATUS "Hajimi TLS Backend : OpenSSL (${HAJIMI_TLS_PREFIX})")
endif()
message(STATUS "Hajimi QUIC/H3     : ${HAJIMI_QUIC_PREFIX}")
message(STATUS "Hajimi libssh2     : ${HAJIMI_SSH_PREFIX}")

find_package(Threads REQUIRED)

# ============================================================================
# L0 Core Data-Plane, Slab Pool, Async Poller, Flow Control & Compiled Routing
# ============================================================================
add_library(HajimiPlatformC INTERFACE)
target_include_directories(HajimiPlatformC INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiPlatformC/include"
)

add_library(HajimiDataPlaneC STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiDataPlaneC/hajimi_dataplane.c"
)
target_include_directories(HajimiDataPlaneC PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiDataPlaneC/include"
)
if(WIN32)
    target_link_libraries(HajimiDataPlaneC PUBLIC ws2_32)
endif()

add_library(HajimiFlowCXX STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiFlowCXX/FlowState.cpp"
)
target_include_directories(HajimiFlowCXX PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiFlowCXX/include"
)

add_library(HajimiProtocolCXX STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolCXX/ProtocolCodec.cpp"
)
target_include_directories(HajimiProtocolCXX PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolCXX/include"
)
if(MSVC)
    target_compile_options(HajimiProtocolCXX PRIVATE /EHs-c- /GR-)
else()
    target_compile_options(HajimiProtocolCXX PRIVATE -fno-exceptions -fno-rtti)
endif()
if(WIN32)
    target_link_libraries(HajimiProtocolCXX PUBLIC ws2_32)
endif()

add_library(HajimiRoutingCXX STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiRoutingCXX/DomainMatcher.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiRoutingCXX/CompiledRules.cpp"
)
target_include_directories(HajimiRoutingCXX PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiRoutingCXX/include"
)
if(WIN32)
    target_link_libraries(HajimiRoutingCXX PUBLIC ws2_32)
endif()

# ============================================================================
# L1 Full 15-Protocol Native Stack (HajimiProtocolsCXX)
# ============================================================================
file(GLOB HAJIMI_PROTOCOLS_CXX_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolsCXX/*.cpp"
)
add_library(HajimiProtocolsCXX STATIC ${HAJIMI_PROTOCOLS_CXX_SOURCES})
target_include_directories(HajimiProtocolsCXX
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolsCXX/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolsCXX"
        "${HAJIMI_TLS_PREFIX}/include"
        "${HAJIMI_QUIC_PREFIX}/include"
        "${HAJIMI_SSH_PREFIX}/include"
)
target_compile_definitions(HajimiProtocolsCXX PUBLIC
    NGTCP2_STATICLIB
    NGHTTP3_STATICLIB
)
if(HAJIMI_USE_AWSLC)
    target_compile_definitions(HajimiProtocolsCXX PUBLIC OPENSSL_IS_AWSLC)
endif()
target_link_libraries(HajimiProtocolsCXX PUBLIC
    HajimiPlatformC
    HajimiProtocolCXX
    "${HAJIMI_LIBNGTCP2_CRYPTO}"
    "${HAJIMI_LIBNGTCP2}"
    "${HAJIMI_LIBNGHTTP3}"
    "${HAJIMI_LIBSSH2}"
    "${HAJIMI_LIBSSL}"
    "${HAJIMI_LIBCRYPTO}"
    Threads::Threads
)
if(WIN32)
    target_link_libraries(HajimiProtocolsCXX PUBLIC ws2_32 crypt32 iphlpapi advapi32 user32 bcrypt)
elseif(APPLE)
    target_compile_definitions(HajimiProtocolsCXX PRIVATE __APPLE_USE_RFC_3542=1)
    target_link_libraries(HajimiProtocolsCXX PUBLIC "-framework Security" "-framework CoreFoundation")
endif()

# ============================================================================
# L2 Unified Async Transport Runtime (kqueue / IOCP / epoll via HajimiAsyncPoller)
# ============================================================================
add_library(HajimiWinTransportCXX STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiWinTransportCXX/HajimiWinTransportCXX.cpp"
)
target_include_directories(HajimiWinTransportCXX
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiWinTransportCXX/include"
    PRIVATE
        "${HAJIMI_TLS_PREFIX}/include"
)
target_link_libraries(HajimiWinTransportCXX PUBLIC HajimiPlatformC HajimiProtocolsCXX)
if(APPLE)
    target_compile_definitions(HajimiWinTransportCXX PRIVATE __APPLE_USE_RFC_3542=1)
    target_link_libraries(HajimiWinTransportCXX PUBLIC "-framework Security" "-framework CoreFoundation")
endif()

# ============================================================================
# L3 Unified Cross-Platform Engine Core & Pure C11 ABI (`libHajimiEngine` / `HajimiEngine.dll`)
# ============================================================================
set(HAJIMI_ENGINE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiEngineCAPI/ProfileConfigParser.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiEngineCAPI/EncryptedDnsAndFakeIp.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiEngineCAPI/WinSystemProxyAndProcess.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiEngineCAPI/UserspacePacketTunnel.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiEngineCAPI/HajimiEngineCAPI.cpp"
)

add_library(HajimiEngineStatic STATIC ${HAJIMI_ENGINE_SOURCES})
target_include_directories(HajimiEngineStatic
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiEngineCAPI/include"
    PRIVATE
        "${HAJIMI_TLS_PREFIX}/include"
)
target_link_libraries(HajimiEngineStatic PUBLIC
    HajimiPlatformC
    HajimiDataPlaneC
    HajimiFlowCXX
    HajimiRoutingCXX
    HajimiProtocolCXX
    HajimiProtocolsCXX
    HajimiWinTransportCXX
)
if(WIN32)
    target_link_libraries(HajimiEngineStatic PUBLIC wininet rasapi32 iphlpapi ws2_32 crypt32)
elseif(APPLE)
    target_compile_definitions(HajimiEngineStatic PRIVATE __APPLE_USE_RFC_3542=1)
    target_link_libraries(HajimiEngineStatic PUBLIC
        "-framework Security"
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
    )
endif()

add_library(HajimiEngine SHARED ${HAJIMI_ENGINE_SOURCES})
target_compile_definitions(HajimiEngine PRIVATE HAJIMI_ENGINE_SHARED_BUILD=1)
target_include_directories(HajimiEngine
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiEngineCAPI/include"
    PRIVATE
        "${HAJIMI_TLS_PREFIX}/include"
)
target_link_libraries(HajimiEngine PRIVATE
    HajimiPlatformC
    HajimiDataPlaneC
    HajimiFlowCXX
    HajimiRoutingCXX
    HajimiProtocolCXX
    HajimiProtocolsCXX
    HajimiWinTransportCXX
)
if(WIN32)
    target_link_libraries(HajimiEngine PRIVATE wininet rasapi32 iphlpapi ws2_32 crypt32)
elseif(APPLE)
    target_compile_definitions(HajimiEngine PRIVATE __APPLE_USE_RFC_3542=1)
    target_link_libraries(HajimiEngine PRIVATE
        "-framework Security"
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
    )
endif()

# Cross-platform Command-Line Host (`hajimi-cli` / `hajimi-cli.exe`)
add_executable(hajimi-cli
    "${CMAKE_CURRENT_SOURCE_DIR}/Windows/HajimiCli/hajimi_cli_main.cpp"
)
target_link_libraries(hajimi-cli PRIVATE HajimiEngineStatic)

# ============================================================================
# L4 Windows Zero-Trust Privileged Helper Service & Portable Launcher
# (macOS uses thin `Sources/HajimiHelper` built via SwiftPM)
# ============================================================================
if(WIN32)
    add_executable(HajimiHelperService
        "${CMAKE_CURRENT_SOURCE_DIR}/Windows/HajimiHelperService/HelperProtocolV8.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/Windows/HajimiHelperService/WintunSessionBridge.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/Windows/HajimiHelperService/RouteAndDnsTransaction.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/Windows/HajimiHelperService/ServiceMain.cpp"
    )
    target_include_directories(HajimiHelperService PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/Windows/HajimiHelperService"
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiPlatformC/include"
    )
    target_link_libraries(HajimiHelperService PRIVATE
        Threads::Threads
        advapi32 iphlpapi ws2_32 fwpuclnt rpcrt4 wintrust crypt32
    )

    add_executable(HajimiPortable
        "${CMAKE_CURRENT_SOURCE_DIR}/Windows/Installer/PortableLauncher/PortableLauncher.cpp"
    )
    target_link_libraries(HajimiPortable PRIVATE shell32)
endif()

# ============================================================================
# M0–M5 Unified Cross-Platform Verification, v2 Batch Benchmark & Interop Suite
# ============================================================================
function(hajimi_keep_test_assertions TGT)
    if(MSVC)
        target_compile_options(${TGT} PRIVATE /UNDEBUG)
    else()
        target_compile_options(${TGT} PRIVATE -UNDEBUG)
    endif()
endfunction()

if(HAJIMI_BUILD_TESTS)
    enable_testing()

    add_executable(dataplane-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/DataPlaneMain.c")
    target_link_libraries(dataplane-check PRIVATE HajimiDataPlaneC)
    hajimi_keep_test_assertions(dataplane-check)
    add_test(NAME dataplane-check COMMAND dataplane-check)

    add_executable(flow-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/FlowStateMain.cpp")
    target_link_libraries(flow-check PRIVATE HajimiFlowCXX)
    hajimi_keep_test_assertions(flow-check)
    add_test(NAME flow-check COMMAND flow-check)

    add_executable(protocol-codec-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/ProtocolCodecMain.cpp")
    target_link_libraries(protocol-codec-check PRIVATE HajimiProtocolCXX)
    hajimi_keep_test_assertions(protocol-codec-check)
    add_test(NAME protocol-codec-check COMMAND protocol-codec-check)

    add_executable(domain-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/DomainMatcherMain.cpp")
    target_link_libraries(domain-check PRIVATE HajimiRoutingCXX)
    hajimi_keep_test_assertions(domain-check)
    add_test(NAME domain-check COMMAND domain-check)

    add_executable(native-compiled-rule-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/CompiledRulesMain.cpp")
    target_link_libraries(native-compiled-rule-check PRIVATE HajimiRoutingCXX Threads::Threads)
    hajimi_keep_test_assertions(native-compiled-rule-check)
    add_test(NAME native-compiled-rule-check COMMAND native-compiled-rule-check)

    add_executable(reader-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/CppReaderPerformanceMain.cpp")
    target_link_libraries(reader-check PRIVATE HajimiProtocolsCXX)
    hajimi_keep_test_assertions(reader-check)
    add_test(NAME reader-check COMMAND reader-check)

    add_executable(dataplane-v2-bench-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/DataPlaneV2BenchMain.cpp")
    target_link_libraries(dataplane-v2-bench-check PRIVATE HajimiEngineStatic)
    hajimi_keep_test_assertions(dataplane-v2-bench-check)
    add_test(NAME dataplane-v2-bench-check COMMAND dataplane-v2-bench-check)

    foreach(SUITE_NAME IN ITEMS Shadowsocks BasicProtocols AnyTLS Snell Server)
        add_executable("${SUITE_NAME}-check"
            "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/Cpp${SUITE_NAME}Main.cpp"
        )
        target_include_directories("${SUITE_NAME}-check" PRIVATE
            "${HAJIMI_TLS_PREFIX}/include"
            "${HAJIMI_QUIC_PREFIX}/include"
            "${HAJIMI_SSH_PREFIX}/include"
        )
        target_link_libraries("${SUITE_NAME}-check" PRIVATE HajimiProtocolsCXX)
        hajimi_keep_test_assertions("${SUITE_NAME}-check")
        add_test(NAME "${SUITE_NAME}-check" COMMAND "${SUITE_NAME}-check")
    endforeach()

    add_executable(win-transport-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/WinTransportMain.cpp")
    target_link_libraries(win-transport-check PRIVATE HajimiWinTransportCXX HajimiProtocolsCXX)
    hajimi_keep_test_assertions(win-transport-check)
    add_test(NAME win-transport-check COMMAND win-transport-check)

    set(HAJIMI_QUIC_BOUNDARY_SOURCES ${HAJIMI_PROTOCOLS_CXX_SOURCES})
    list(REMOVE_ITEM HAJIMI_QUIC_BOUNDARY_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolsCXX/QUICTransport.cpp"
    )
    add_executable(quic-boundary-check
        "${CMAKE_CURRENT_SOURCE_DIR}/NativeTests/QUICBoundaryChecks.cpp"
        ${HAJIMI_QUIC_BOUNDARY_SOURCES}
    )
    target_include_directories(quic-boundary-check PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolsCXX"
        "${CMAKE_CURRENT_SOURCE_DIR}/Sources/HajimiProtocolsCXX/include"
        "${HAJIMI_TLS_PREFIX}/include"
        "${HAJIMI_QUIC_PREFIX}/include"
        "${HAJIMI_SSH_PREFIX}/include"
    )
    target_compile_definitions(quic-boundary-check PRIVATE NGTCP2_STATICLIB NGHTTP3_STATICLIB)
    if(HAJIMI_USE_AWSLC)
        target_compile_definitions(quic-boundary-check PRIVATE OPENSSL_IS_AWSLC)
    endif()
    if(APPLE)
        target_compile_definitions(quic-boundary-check PRIVATE __APPLE_USE_RFC_3542=1)
    endif()
    target_link_libraries(quic-boundary-check PRIVATE
        HajimiPlatformC
        HajimiProtocolCXX
        "${HAJIMI_LIBNGTCP2_CRYPTO}"
        "${HAJIMI_LIBNGTCP2}"
        "${HAJIMI_LIBNGHTTP3}"
        "${HAJIMI_LIBSSH2}"
        "${HAJIMI_LIBSSL}"
        "${HAJIMI_LIBCRYPTO}"
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(quic-boundary-check PRIVATE ws2_32 crypt32 iphlpapi advapi32 user32 bcrypt)
    elseif(APPLE)
        target_link_libraries(quic-boundary-check PRIVATE "-framework Security" "-framework CoreFoundation")
    endif()
    hajimi_keep_test_assertions(quic-boundary-check)
    add_test(NAME quic-boundary-check COMMAND quic-boundary-check)

    add_executable(engine-loopback-check
        "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/EngineLoopbackMain.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/Windows/HajimiHelperService/HelperProtocolV8.cpp"
    )
    target_link_libraries(engine-loopback-check PRIVATE HajimiEngineStatic)
    hajimi_keep_test_assertions(engine-loopback-check)
    add_test(NAME engine-loopback-check COMMAND engine-loopback-check)

    add_executable(parser-regression-check
        "${CMAKE_CURRENT_SOURCE_DIR}/Tests/EngineLoopback/ParserRealWorldRegressionMain.cpp"
    )
    target_link_libraries(parser-regression-check PRIVATE HajimiEngineStatic)
    hajimi_keep_test_assertions(parser-regression-check)
    add_test(NAME parser-regression-check COMMAND parser-regression-check)

    add_test(NAME hajimi-cli-self-test COMMAND hajimi-cli --self-test)
    if(WIN32)
        add_test(NAME helper-service-self-test COMMAND HajimiHelperService --self-test)
        add_test(NAME portable-launcher-self-test COMMAND HajimiPortable --self-test)
    endif()

    add_executable(SSH-check "${CMAKE_CURRENT_SOURCE_DIR}/SmokeTests/CppSSHMain.cpp")
    target_include_directories(SSH-check PRIVATE "${HAJIMI_SSH_PREFIX}/include")
    target_link_libraries(SSH-check PRIVATE HajimiProtocolsCXX)
    hajimi_keep_test_assertions(SSH-check)

    add_executable(quic-check "${CMAKE_CURRENT_SOURCE_DIR}/NativeTests/QUICInteropClient.cpp")
    target_compile_definitions(quic-check PRIVATE HAJIMI_QUIC_DIAGNOSTICS)
    target_link_libraries(quic-check PRIVATE HajimiProtocolsCXX)
    hajimi_keep_test_assertions(quic-check)
endif()
