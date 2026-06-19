cmake_minimum_required(VERSION 3.22)

project(aes_model C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(AES_SOURCES
    src/aes_transformation.c
    src/aes_key_expansion.c
    src/aes_math.c
    src/aes.c
)

add_executable(aes_model
    src/main.c
    ${AES_SOURCES}
)

add_executable(aes_tests
    test/test_aes.c
    ${AES_SOURCES}
)

target_include_directories(aes_model PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(aes_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(aes_model PRIVATE
    -Wall
    -Wextra
)

target_compile_options(aes_tests PRIVATE
    -Wall
    -Wextra
)

enable_testing()

add_test(NAME aes_tests COMMAND aes_tests)