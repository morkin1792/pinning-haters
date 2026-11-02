cmake_minimum_required(VERSION 3.22)
project(pinning_haters CXX)

# ARM64 only (see AGENTS.md "Why ARM64-only"). x86_64 is backlog; ARM32 out of scope.
if(ANDROID AND NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "pinning-haters builds for arm64-v8a only (got ${ANDROID_ABI})")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT PH_VERSION)
    set(PH_VERSION "dev")
endif()
option(PH_DEBUG_LOGCAT "Also print log lines to logcat (debug builds only; never ship)" OFF)

add_library(pinning_haters SHARED
    module.cpp
    companion.cpp
    config/config.cpp
    log/log.cpp
    got/got_hook.cpp
    art/art_api.cpp
    art/aot_fallback.cpp
    dex/dex_parser.cpp
    dex/dex_patcher.cpp
    dex/dex_intercept.cpp
    tls/conscrypt_wrap.cpp
    tls/bundled_tls.cpp
    tls/boringssl_table.cpp
    tls/openssl_table.cpp
    hooks/hook_manager.cpp
    hide/self_remap.cpp
    hooks/targets_java.cpp
    hooks/targets_native.cpp
)

target_compile_definitions(pinning_haters PRIVATE PH_VERSION="${PH_VERSION}")
if(PH_DEBUG_LOGCAT)
    target_compile_definitions(pinning_haters PRIVATE PH_DEBUG_LOGCAT=1)
endif()

# No exceptions, no RTTI on hook paths. Only the companion-side config parser (nlohmann/json) gets
# exceptions, and it never runs inside an app process.
target_compile_options(pinning_haters PRIVATE
    -Wall -Wextra -Werror=return-type
    -fvisibility=hidden -fno-exceptions -fno-rtti
    -ffunction-sections -fdata-sections
    -fno-asynchronous-unwind-tables)
set_source_files_properties(companion.cpp config/config.cpp PROPERTIES COMPILE_OPTIONS "-fexceptions")

target_link_options(pinning_haters PRIVATE
    -Wl,--gc-sections -Wl,--exclude-libs,ALL -Wl,-z,relro -Wl,-z,now -Wl,--no-undefined -Wl,--build-id=none
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map)
set_target_properties(pinning_haters PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/exports.map)
target_link_libraries(pinning_haters PRIVATE log)

# Zygisk expects zygisk/<abi>.so at the module root.
set_target_properties(pinning_haters PROPERTIES PREFIX "" OUTPUT_NAME "arm64-v8a" SUFFIX ".so")
