cmake_minimum_required(VERSION 3.22)
project(pinning_haters_host_tests CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(JNI ${CMAKE_CURRENT_SOURCE_DIR}/../module/jni)

add_executable(test_dex_patcher dex_patcher/test_dex_patcher.cpp
    ${JNI}/dex/dex_parser.cpp ${JNI}/dex/dex_patcher.cpp ${JNI}/hooks/targets_java.cpp)
target_include_directories(test_dex_patcher PRIVATE ${JNI})
target_link_libraries(test_dex_patcher PRIVATE z)

add_executable(test_got host/test_got.cpp ${JNI}/got/got_hook.cpp)
target_include_directories(test_got PRIVATE ${JNI})
target_link_libraries(test_got PRIVATE pthread)

add_executable(test_config host/test_config.cpp ${JNI}/config/config.cpp)
target_include_directories(test_config PRIVATE ${JNI})

add_executable(test_boringssl_table host/test_boringssl_table.cpp ${JNI}/tls/boringssl_table.cpp ${JNI}/tls/openssl_table.cpp ${JNI}/got/got_hook.cpp)
target_include_directories(test_boringssl_table PRIVATE ${JNI})
target_link_libraries(test_boringssl_table PRIVATE pthread)

add_executable(test_self_remap host/test_self_remap.cpp ${JNI}/hide/self_remap.cpp)
target_include_directories(test_self_remap PRIVATE ${JNI})

foreach(t test_dex_patcher test_got test_config test_boringssl_table test_self_remap)
    target_compile_options(${t} PRIVATE -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer -g)
    target_link_options(${t} PRIVATE -fsanitize=address,undefined)
endforeach()
